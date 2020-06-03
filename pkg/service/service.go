package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/alvarobacelar/prometheus-msteams/pkg/card"
	"github.com/prometheus/alertmanager/notify/webhook"
	"go.opencensus.io/trace"
)

// PostResponse is the prometheus msteams service response.
type PostResponse struct {
	WebhookURL string `json:"webhook_url"`
	Status     int    `json:"status"`
	Message    string `json:"message"`
}

// StsToken get token to request
type StsToken struct {
	accessToken  string `json:"access_token"`
	tokenType    string `json:"token_type"`
	tokenExpires string `json:"expires_in"`
}

// TokenTeams gard token
type TokenTeams struct {
	accessTokenTeam string
	expiresIn       string
}

// StsRequest info aboult request token
type StsRequest struct {
	clientID     string
	clientSecret string
	urlSTS       string
	client       *http.Client
}

// Service is the Alertmanager to Microsoft Teams webhook service.
type Service interface {
	Post(context.Context, webhook.Message) (resp []PostResponse, err error)
}

type simpleService struct {
	converter  card.Converter
	client     *http.Client
	webhookURL string
}

// NewSimpleService creates a simpleService.
func NewSimpleService(converter card.Converter, client *http.Client, webhookURL string) Service {
	return simpleService{converter, client, webhookURL}
}

// NewSTSRequest is first request to get token
func NewSTSRequest(clientID string, clientSecret string, urlSTS string) StsRequest {
	return StsRequest{clientID: clientID, clientSecret: clientSecret, urlSTS: urlSTS}
}

func (t *StsRequest) requestTokenSts() (TokenTeams, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_secret", t.clientSecret)
	data.Set("client_id", t.clientID)
	pr := StsToken{}
	tr := TokenTeams{}

	req, err := http.NewRequest("POST", t.urlSTS, strings.NewReader(data.Encode()))
	if err != nil {
		err = fmt.Errorf("failed to creating a request: %w", err)
		return tr, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("x-itau-flowID", "11")
	req.Header.Add("x-itau-correlationID", "22")
	fmt.Printf("========>>>> Requisição %s", req)
	resp, err := t.client.Do(req)
	if err != nil {
		err = fmt.Errorf("http client failed: %w", err)
		return tr, err
	}
	defer resp.Body.Close()

	rb, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		err = fmt.Errorf("failed reading http response body: %w", err)
		return tr, err
	}

	json.Unmarshal(rb, &pr)
	if err != nil {
		log.Println(err)
	}

	tr.accessTokenTeam = pr.accessToken
	tr.expiresIn = pr.tokenExpires

	return tr, nil
}

func (s simpleService) Post(ctx context.Context, wm webhook.Message) ([]PostResponse, error) {
	ctx, span := trace.StartSpan(ctx, "simpleService.Post")
	defer span.End()

	prs := []PostResponse{}

	c, err := s.converter.Convert(ctx, wm)
	if err != nil {
		return nil, fmt.Errorf("failed to parse webhook message: %w", err)
	}

	// Split into multiple messages if necessary.
	cc, err := splitOffice365Card(c)
	if err != nil {
		return nil, fmt.Errorf("failed to split Office 365 Card: %w", err)
	}

	// TODO(@bzon): post concurrently.
	for _, c := range cc {
		pr, err := s.post(ctx, c, s.webhookURL)
		prs = append(prs, pr)
		if err != nil {
			return prs, err
		}
	}

	return prs, nil
}

func (s simpleService) post(ctx context.Context, c card.Office365ConnectorCard, url string) (PostResponse, error) {
	ctx, span := trace.StartSpan(ctx, "simpleService.post")
	defer span.End()

	pr := PostResponse{WebhookURL: url}
	tk := requestTokenSts()

	b, err := json.Marshal(c)
	if err != nil {
		err = fmt.Errorf("failed to decoding JSON card: %w", err)
		return pr, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.webhookURL, bytes.NewBuffer(b))
	if err != nil {
		err = fmt.Errorf("failed to creating a request: %w", err)
		return pr, err
	}

	req.Header.Add("Cookie", "ClientId=06C5801E46D26AB227488E4142D26C70; OIDC=1")
	req.Header.Add("x-itau-apikey", "4a4c1d1b-b7f3-4590-805b-4959d475ff1a")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer: "+tk.accessTokenTeam)
	resp, err := s.client.Do(req)
	if err != nil {
		err = fmt.Errorf("http client failed: %w", err)
		return pr, err
	}
	defer resp.Body.Close()

	pr.Status = resp.StatusCode

	if pr.Status == 403 {

	}

	rb, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		err = fmt.Errorf("failed reading http response body: %w", err)
		pr.Message = err.Error()
		return pr, err
	}
	pr.Message = string(rb)

	return pr, nil
}

// splitOffice365Card splits a single Office365ConnectorCard into multiple Office365ConnectorCard.
// The purpose of doing this is to prevent getting limited by Microsoft Teams API when sending a large JSON payload.
func splitOffice365Card(c card.Office365ConnectorCard) ([]card.Office365ConnectorCard, error) {
	// Maximum message size of 14336 Bytes (14KB)
	const maxSize = 14336
	// Maximum number of sections
	// ref: https://docs.microsoft.com/en-us/microsoftteams/platform/concepts/cards/cards-reference#notes-on-the-office-365-connector-card
	const maxCardSections = 10

	var cards []card.Office365ConnectorCard

	// marshal cards in order to get the byte size
	cb, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}

	// Everything is good.
	if (len(c.Sections) < maxCardSections) && (len(cb) < maxSize) {
		cards = append(cards, c)
		return cards, nil
	}

	indexAdded := make(map[int]bool)

	// Here, we keep creating a new card until all sections are transferred into a new card.
	for len(indexAdded) != len(c.Sections) {
		newCard := c // take all the attributes
		newCard.Sections = nil

		for i, s := range c.Sections {
			if _, ok := indexAdded[i]; ok { // check if the index is already added.
				continue
			}

			// marshal cards in order to get the byte size
			newCardb, err := json.Marshal(newCard)
			if err != nil {
				return nil, err
			}

			// If the max length or size has exceeded the limit,
			// break the loop so we can create a new card again.
			if (len(newCard.Sections) >= maxCardSections) || (len(newCardb) >= maxSize) {
				break
			}

			newCard.Sections = append(newCard.Sections, s)
			indexAdded[i] = true
		}

		cards = append(cards, newCard)
	}

	return cards, nil
}
