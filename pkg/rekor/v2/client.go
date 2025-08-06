// Copyright 2025 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v2

import (
	"context"
	"fmt"
	"net/url"
	"time"

	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	tiles_client "github.com/sigstore/rekor-tiles/pkg/client"
	"github.com/sigstore/rekor-tiles/pkg/client/read"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore/pkg/signature"
)

type ShardInfo struct {
	client      *read.Client
	verifier    *signature.Verifier
	validityEnd time.Time
}

func RefreshSigningConfig(tufClient *tuf.Client) (*root.SigningConfig, error) {
	err := tufClient.Refresh()
	if err != nil {
		return nil, fmt.Errorf("error refreshing TUF client: %v", err)
	}

	signingConfig, err := root.GetSigningConfig(tufClient)
	if err != nil {
		return nil, fmt.Errorf("error getting SigningConfig target: %v", err)
	}
	return signingConfig, nil
}

func ShardsNeedUpdating(currentShards map[string]ShardInfo, newSigningConfig *root.SigningConfig) (bool, error) {
	allRekorServices := newSigningConfig.RekorLogURLs()
	if len(allRekorServices) == 0 {
		return false, fmt.Errorf("error fetching Rekor shards: no shards found in SigningConfig")
	}

	newestShardURL, err := url.Parse(allRekorServices[0].URL)
	if err != nil {
		return false, fmt.Errorf("error parsing rekor shard URL: %v", err)
	}
	newestShardOrigin, err := getOrigin(newestShardURL)
	if err != nil {
		return false, err
	}

	matchingShard, ok := currentShards[newestShardOrigin]
	if !ok {
		// The newest shard in the SigningConfig is not present
		// in the existing shards, so we need to update
		return true, nil
	} else if matchingShard.validityEnd != allRekorServices[0].ValidityPeriodEnd {
		// The newest shard in the SigningConfig is present in
		// the existing shards, but the end validity time changed
		return true, nil
	} else {
		return false, nil
	}
}

func GetRekorShards(ctx context.Context, trustedRoot *root.TrustedRoot, rekorServices []root.Service, userAgent string) (map[string]ShardInfo, string, error) {
	rekorServices, err := root.SelectServices(rekorServices, root.ServiceConfiguration{Selector: prototrustroot.ServiceSelector_ALL}, []uint32{2}, time.Now())
	if err != nil {
		return nil, "", fmt.Errorf("error selecting rekor services: %v", err)
	}

	rekorShards := make(map[string]ShardInfo)
	activeShardOrigin := ""
	for _, service := range rekorServices {
		parsedURL, err := url.Parse(service.URL)
		if err != nil {
			return nil, "", fmt.Errorf("error parsing Rekor url: %v", err)
		}
		origin, err := getOrigin(parsedURL)
		if err != nil {
			return nil, "", err
		}

		// The services in rekorServices are ordered from newest to oldest,
		// so we store the origin of the first one as the origin
		// of the latest (active) shard
		if activeShardOrigin == "" {
			activeShardOrigin = origin
		}
		verifier, err := GetLogVerifier(ctx, parsedURL, trustedRoot, userAgent)
		if err != nil {
			return nil, "", err
		}

		rekorClient, err := read.NewReader(service.URL, origin, verifier, tiles_client.WithUserAgent(userAgent))
		if err != nil {
			return nil, "", fmt.Errorf("getting Rekor client: %v", err)
		}

		// ReadCheckpoint fetches and verifies the current checkpoint
		// We verify the checkpoints of all active v2 shards
		checkpoint, _, err := rekorClient.ReadCheckpoint(ctx)
		if err != nil {
			return nil, "", fmt.Errorf("failed to get current checkpoint for log '%v': %v", origin, err)
		}

		rekorShards[checkpoint.Origin] = ShardInfo{&rekorClient, &verifier, service.ValidityPeriodEnd}
	}
	return rekorShards, activeShardOrigin, nil
}

func getOrigin(shardURL *url.URL) (string, error) {
	prefixLen := len(shardURL.Scheme) + len("://")
	if prefixLen >= len(shardURL.String()) {
		return "", fmt.Errorf("error getting origin from URL %v", shardURL)
	}
	origin := shardURL.String()[len(shardURL.Scheme)+len("://"):]
	return origin, nil
}
