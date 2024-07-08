package emailverifier

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// updateDisposableDomains gets domains data from source's URL
func updateDisposableDomains(source string, updater DisposableRepoUpdater) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequest("GET", source, nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("get disposable domains from %s with status_code: %d", source, resp.StatusCode)
	}

	var domains []string

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if len(content) == 0 {
		return nil
	}

	if err = json.Unmarshal(content, &domains); err != nil {
		return err
	}

	updater.AddDisposableDomains(domains)

	return nil
}
