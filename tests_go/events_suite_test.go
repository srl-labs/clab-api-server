// tests_go/events_suite_test.go
package tests_go

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type EventsSuite struct {
	BaseSuite
	apiUserToken     string
	apiUserHeaders   http.Header
	superuserToken   string
	superuserHeaders http.Header

	apiLabName string
	suLabName  string
}

const initialEventSettleWindow = 500 * time.Millisecond

func TestEventsSuite(t *testing.T) {
	suite.Run(t, new(EventsSuite))
}

func (s *EventsSuite) SetupSuite() {
	s.BaseSuite.SetupSuite()

	s.apiUserToken = s.login(s.cfg.APIUserUser, s.cfg.APIUserPass)
	s.apiUserHeaders = s.getAuthHeaders(s.apiUserToken)
	s.superuserToken = s.login(s.cfg.SuperuserUser, s.cfg.SuperuserPass)
	s.superuserHeaders = s.getAuthHeaders(s.superuserToken)
	s.Require().NotEmpty(s.apiUserToken)
	s.Require().NotEmpty(s.superuserToken)

	s.apiLabName = fmt.Sprintf("%s-events-%s", s.cfg.LabNamePrefix, s.randomSuffix(5))
	apiTopology := strings.ReplaceAll(s.cfg.SimpleTopologyContent, "{lab_name}", s.apiLabName)
	s.logSetup("Creating API user events lab: %s", s.apiLabName)
	bodyBytes, statusCode, err := s.createLab(s.apiUserHeaders, s.apiLabName, apiTopology, false, s.cfg.DeployTimeout)
	s.Require().NoError(err, "SETUP Failed: Could not create API user events lab")
	s.Require().Equal(http.StatusOK, statusCode, "SETUP Failed: Could not create API user events lab. Body: %s", string(bodyBytes))

	s.suLabName = fmt.Sprintf("%s-events-su-%s", s.cfg.LabNamePrefix, s.randomSuffix(5))
	suTopology := strings.ReplaceAll(s.cfg.SimpleTopologyContent, "{lab_name}", s.suLabName)
	s.logSetup("Creating superuser events lab: %s", s.suLabName)
	bodyBytes, statusCode, err = s.createLab(s.superuserHeaders, s.suLabName, suTopology, false, s.cfg.DeployTimeout)
	s.Require().NoError(err, "SETUP Failed: Could not create superuser events lab")
	s.Require().Equal(http.StatusOK, statusCode, "SETUP Failed: Could not create superuser events lab. Body: %s", string(bodyBytes))

	s.logDebug("Pausing for lab stabilization...")
	time.Sleep(s.cfg.StabilizePause)
}

func (s *EventsSuite) TearDownSuite() {
	if s.suLabName != "" {
		s.logTeardown("Cleaning up superuser events lab: %s", s.suLabName)
		_, _, err := s.destroyLab(s.superuserHeaders, s.suLabName, true, s.cfg.CleanupTimeout)
		if err != nil {
			s.logWarning("Error during superuser events lab cleanup: %v", err)
		}
		time.Sleep(s.cfg.CleanupPause)
	}

	if s.apiLabName != "" {
		s.logTeardown("Cleaning up API user events lab: %s", s.apiLabName)
		_, _, err := s.destroyLab(s.superuserHeaders, s.apiLabName, true, s.cfg.CleanupTimeout)
		if err != nil {
			s.logWarning("Error during API user events lab cleanup: %v", err)
		}
		time.Sleep(s.cfg.CleanupPause)
	}

	s.BaseSuite.TearDownSuite()
}

func (s *EventsSuite) TestEventsStreamJSONFiltersByLab() {
	s.logTest("Streaming JSON events as API user (expecting only labs owned by the API user)")

	// Build the set of labs visible to the API user.
	listURL := fmt.Sprintf("%s/api/v1/labs", s.cfg.APIURL)
	listBytes, listStatus, listErr := s.doRequest("GET", listURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(listErr, "Failed to list labs for API user")
	s.Require().Equal(http.StatusOK, listStatus, "Expected status 200 listing labs for API user")

	var labsData ClabInspectOutput
	listDecodeErr := json.Unmarshal(listBytes, &labsData)
	s.Require().NoError(listDecodeErr, "Failed to decode labs list. Body: %s", string(listBytes))

	allowedLabs := make(map[string]struct{}, len(labsData))
	for lab := range labsData {
		allowedLabs[lab] = struct{}{}
	}
	_, expectedLabPresent := allowedLabs[s.apiLabName]
	s.Require().True(expectedLabPresent, "Expected API user lab '%s' to be visible in /api/v1/labs", s.apiLabName)

	eventsURL := fmt.Sprintf("%s/api/v1/events?initialState=true", s.cfg.APIURL)
	seenExpectedLab := false
	lines, statusCode, err := s.collectEventLinesUntil(eventsURL, s.apiUserHeaders, s.streamTimeout(), initialEventSettleWindow, func(line string) bool {
		attrs, parseErr := parseEventAttributes(line)
		if parseErr == nil && eventLabName(attrs) == s.apiLabName {
			seenExpectedLab = true
		}
		return seenExpectedLab
	})
	s.Require().NoError(err, "Failed to stream events")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 for events stream")
	s.Require().NotEmpty(lines, "Expected at least one event line")
	s.Require().True(seenExpectedLab, "Expected event stream to include API user lab '%s'", s.apiLabName)

	for _, line := range lines {
		attrs, parseErr := parseEventAttributes(line)
		s.Require().NoError(parseErr, "Failed to parse JSON event line: %s", line)
		lab := eventLabName(attrs)
		s.Require().NotEmpty(lab, "Expected lab attribute on event line: %s", line)
		_, ok := allowedLabs[lab]
		s.Assert().True(ok, "API user should only see events for labs they own, got '%s'", lab)
	}

	if !s.T().Failed() {
		s.logSuccess("API user event stream filtered correctly for owned labs")
	}
}

func (s *EventsSuite) TestEventsStreamJSONSuperuserSeesBothLabs() {
	s.logTest("Streaming JSON events as superuser (expecting labs '%s' and '%s')", s.apiLabName, s.suLabName)

	eventsURL := fmt.Sprintf("%s/api/v1/events?initialState=true", s.cfg.APIURL)
	seenAPI := false
	seenSU := false
	lines, statusCode, err := s.collectEventLinesUntil(eventsURL, s.superuserHeaders, s.streamTimeout(), initialEventSettleWindow, func(line string) bool {
		attrs, parseErr := parseEventAttributes(line)
		if parseErr != nil {
			return seenAPI && seenSU
		}
		lab := eventLabName(attrs)
		if lab == s.apiLabName {
			seenAPI = true
		}
		if lab == s.suLabName {
			seenSU = true
		}
		return seenAPI && seenSU
	})
	s.Require().NoError(err, "Failed to stream events")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 for events stream")
	s.Require().NotEmpty(lines, "Expected at least one event line")

	for _, line := range lines {
		_, parseErr := parseEventAttributes(line)
		s.Require().NoError(parseErr, "Failed to parse JSON event line: %s", line)
	}

	s.Assert().True(seenAPI, "Superuser should see events for API user lab '%s'", s.apiLabName)
	s.Assert().True(seenSU, "Superuser should see events for superuser lab '%s'", s.suLabName)

	if !s.T().Failed() {
		s.logSuccess("Superuser event stream included both labs")
	}
}

func (s *EventsSuite) TestEventsStreamJSONLifecycleMessages() {
	s.logTest("Streaming JSON events while creating and destroying a lab (expecting lifecycle and interface events)")

	labName := fmt.Sprintf("%s-events-life-%s", s.cfg.LabNamePrefix, s.randomSuffix(5))
	topology := strings.ReplaceAll(s.cfg.SimpleTopologyContent, "{lab_name}", labName)
	// Without initialState, an interface event needs a link to change after the server starts
	// watching a node, and a lab's links can already be up by then.
	eventsURL := fmt.Sprintf("%s/api/v1/events?initialState=true", s.cfg.APIURL)

	ctx, cancel := context.WithTimeout(context.Background(), s.lifecycleTimeout())
	defer cancel()

	linesCh, errCh, err := s.startEventStream(ctx, eventsURL, s.apiUserHeaders)
	s.Require().NoError(err, "Failed to start events stream")

	bodyBytes, statusCode, err := s.createLab(s.apiUserHeaders, labName, topology, false, s.cfg.DeployTimeout)
	s.Require().NoError(err, "Failed to create lifecycle lab")
	s.Require().Equal(http.StatusOK, statusCode, "Failed to create lifecycle lab. Body: %s", string(bodyBytes))

	seenContainerCreate := false
	seenContainerStart := false
	seenContainerStop := false
	seenInterfaceEvent := false

	// readEventsUntil reads the stream until done reports true, the stream ends or ctx expires.
	readEventsUntil := func(done func() bool) {
		for !done() {
			select {
			case line, ok := <-linesCh:
				if !ok {
					return
				}
				ev, parseErr := parseEventLine(line)
				if parseErr != nil {
					continue
				}
				if eventLabName(ev.Attributes) != labName {
					continue
				}
				switch ev.Type {
				case "container":
					switch ev.Action {
					case "create":
						seenContainerCreate = true
					case "start":
						seenContainerStart = true
					case "die", "destroy", "stop":
						seenContainerStop = true
					}
				case "interface":
					seenInterfaceEvent = true
				}
			case err := <-errCh:
				if err != nil {
					s.logWarning("Events stream error: %v", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}

	// The lab has to stay up until its interfaces are reported: the server stops watching a
	// node once its container stops.
	readEventsUntil(func() bool {
		return seenContainerCreate && seenContainerStart && seenInterfaceEvent
	})

	_, statusCode, err = s.destroyLab(s.apiUserHeaders, labName, true, s.cfg.CleanupTimeout)
	s.Require().NoError(err, "Failed to destroy lifecycle lab")
	s.Require().Equal(http.StatusOK, statusCode, "Failed to destroy lifecycle lab")

	readEventsUntil(func() bool { return seenContainerStop })

	cancel()

	s.Assert().True(seenContainerCreate, "Expected container create event for lab '%s'", labName)
	s.Assert().True(seenContainerStart, "Expected container start event for lab '%s'", labName)
	s.Assert().True(seenContainerStop, "Expected container stop/die/destroy event for lab '%s'", labName)
	s.Assert().True(seenInterfaceEvent, "Expected interface event for lab '%s'", labName)

	if !s.T().Failed() {
		s.logSuccess("Lifecycle event stream captured container and interface events for lab '%s'", labName)
	}
}

func (s *EventsSuite) collectEventLinesUntil(url string, headers http.Header, timeout, settleWindow time.Duration, done func(string) bool) ([]string, int, error) {
	s.T().Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header = headers

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, resp.StatusCode, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lines := make([]string, 0, 16)
	conditionMet := false
	var settleTimer *time.Timer
	defer func() {
		if settleTimer != nil {
			settleTimer.Stop()
		}
	}()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lines = append(lines, line)
		if !conditionMet && done != nil {
			conditionMet = done(line)
		}
		if conditionMet {
			if settleWindow <= 0 {
				cancel()
				break
			}
			if settleTimer == nil {
				settleTimer = time.AfterFunc(settleWindow, cancel)
			} else {
				settleTimer.Reset(settleWindow)
			}
		}
	}

	if err := scanner.Err(); err != nil && ctx.Err() == nil {
		return lines, resp.StatusCode, fmt.Errorf("scanner error: %w", err)
	}

	return lines, resp.StatusCode, nil
}

func (s *EventsSuite) startEventStream(ctx context.Context, url string, headers http.Header) (<-chan string, <-chan error, error) {
	s.T().Helper()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header = headers

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to execute request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	lines := make(chan string, 128)
	errs := make(chan error, 1)

	go func() {
		defer close(lines)
		defer close(errs)
		defer resp.Body.Close()

		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			select {
			case lines <- line:
			case <-ctx.Done():
				return
			}
		}
		if err := scanner.Err(); err != nil && ctx.Err() == nil {
			errs <- err
		}
	}()

	return lines, errs, nil
}

func (s *EventsSuite) streamTimeout() time.Duration {
	if s.cfg.RequestTimeout < 15*time.Second {
		return 15 * time.Second
	}
	return s.cfg.RequestTimeout
}

func (s *EventsSuite) lifecycleTimeout() time.Duration {
	timeout := s.cfg.DeployTimeout + s.cfg.CleanupTimeout
	if timeout < 45*time.Second {
		timeout = 45 * time.Second
	}
	if timeout > 2*time.Minute {
		timeout = 2 * time.Minute
	}
	return timeout
}

type eventLine struct {
	Type       string            `json:"type"`
	Action     string            `json:"action"`
	Attributes map[string]string `json:"attributes"`
}

func parseEventLine(line string) (*eventLine, error) {
	var evt eventLine
	if err := json.Unmarshal([]byte(line), &evt); err != nil {
		return nil, err
	}
	return &evt, nil
}

func parseEventAttributes(line string) (map[string]string, error) {
	var evt struct {
		Attributes map[string]string `json:"attributes"`
	}
	if err := json.Unmarshal([]byte(line), &evt); err != nil {
		return nil, err
	}
	return evt.Attributes, nil
}

func eventLabName(attrs map[string]string) string {
	if attrs == nil {
		return ""
	}
	if lab := attrs["lab"]; lab != "" {
		return lab
	}
	return attrs["containerlab"]
}
