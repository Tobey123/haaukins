// Copyright (c) 2018-2019 Aalborg University
// Use of this source code is governed by a GPLv3
// license that can be found in the LICENSE file.

package store_test

import (
	"errors"
	"testing"

	"github.com/aau-network-security/haaukins/store"
)

type exer struct {
	name string
	tags []store.Tag
}

func TestNewExerciseStore(t *testing.T) {
	tt := []struct {
		name string
		in   []exer
		err  string
	}{
		{name: "Normal", in: []exer{{name: "Test", tags: []store.Tag{"tst"}}}},
		{name: "Multiple tags", in: []exer{{name: "Test", tags: []store.Tag{"tst", "tst2"}}}},
		{name: "Identical tags", in: []exer{
			{name: "Test", tags: []store.Tag{"tst"}},
			{name: "Test 2", tags: []store.Tag{"tst"}},
		}, err: "Tag already exists: tst"}}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			var exers []store.ChallengeConfig
			var tags []store.Tag
			for _, e := range tc.in {
				exers = append(exers, store.ChallengeConfig{
					Name: e.name,
					Tags: e.tags,
				})

				tags = append(tags, e.tags...)
			}

			es, err := store.NewChallengeStore(exers)
			if err != nil {
				if tc.err != "" {
					if tc.err != err.Error() {
						t.Fatalf("unexpected error (expected: \"%s\") when creating store: %s", tc.err, err)
					}

					return
				}

				t.Fatalf("received error when creating challenge store, but expected none: %s", err)
			}

			if tc.err != "" {
				t.Fatalf("received no error when expecting: %s", tc.err)
			}

			if n := len(es.ListChallenges()); n != len(exers) {
				t.Fatalf("unexpected amount of challenges, expected: %d, got: %d", len(exers), n)
			}

			exercises, err := es.GetChallengesByTags(tags...)
			if err != nil {
				t.Fatalf("unexpected error when looking up tags")
			}

			if n := len(exercises); n != len(tags) {
				t.Fatalf("unexpected amount of challenges when looking up, expected: %d, got: %d", len(tags), n)
			}

		})
	}
}

func TestCreateExercise(t *testing.T) {
	tt := []struct {
		name string
		in   exer
		err  bool
	}{
		{name: "Normal", in: exer{name: "Test", tags: []store.Tag{"tst"}}},
		{name: "Invalid tag challenge", in: exer{name: "Test", tags: []store.Tag{"tst tst"}}, err: true},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			var ran bool
			var count int
			var errToThrow error

			hook := func(e []store.ChallengeConfig) error {
				count = len(e)
				ran = true

				return errToThrow
			}

			es, err := store.NewChallengeStore([]store.ChallengeConfig{}, hook)
			if err != nil {
				t.Fatalf("received error when creating challenge store, but expected none: %s", err)
			}

			err = es.CreateChallenge(store.ChallengeConfig{
				Name: tc.in.name,
				Tags: tc.in.tags,
			})
			if err != nil {
				if !tc.err {
					t.Fatalf("unexpected error: %s", err)
				}

				return
			}

			if tc.err {
				t.Fatalf("received no error, but expected error")
			}

			if !ran {
				t.Fatalf("expected hook to have been run")
			}

			if count != 1 {
				t.Fatalf("expected hook to have been run with one challenge")
			}

			es, err = store.NewChallengeStore([]store.ChallengeConfig{}, hook)
			if err != nil {
				t.Fatalf("received error when creating challenge store, but expected none: %s", err)
			}

			errToThrow = errors.New("Some error")
			err = es.CreateChallenge(store.ChallengeConfig{
				Name: tc.in.name,
				Tags: tc.in.tags,
			})
			if err == nil {
				t.Fatalf("expected hook to have thrown error")
			}
		})
	}
}

func TestGetExercises(t *testing.T) {
	tt := []struct {
		name    string
		in      []exer
		lookups []store.Tag
		err     string
	}{
		{name: "Normal", in: []exer{
			exer{name: "Test", tags: []store.Tag{"tst"}},
		}, lookups: []store.Tag{"tst"}},
		{name: "Normal (pool of two)", in: []exer{
			exer{name: "Test", tags: []store.Tag{"tst"}},
			exer{name: "Test2", tags: []store.Tag{"tst2"}},
		}, lookups: []store.Tag{"tst"}},
		{name: "Unknown challenge", in: []exer{},
			err:     "Unknown challenge tag: tst",
			lookups: []store.Tag{"tst"}},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			var exer []store.ChallengeConfig
			for _, e := range tc.in {
				exer = append(exer, store.ChallengeConfig{
					Name: e.name,
					Tags: e.tags,
				})
			}

			es, err := store.NewChallengeStore(exer)
			if err != nil {
				t.Fatalf("received error when creating challenge store, but expected none: %s", err)
			}

			exercises, err := es.GetChallengesByTags(tc.lookups...)
			if err != nil {
				if tc.err != "" {
					if tc.err != err.Error() {
						t.Fatalf("unexpected error (expected: \"%s\") when creating store: %s", tc.err, err)
					}

					return
				}

				t.Fatalf("unexpected error: %s", err)
			}

			if tc.err != "" {
				t.Fatalf("received no error, but expected error")
			}

			if n := len(exercises); n != len(tc.lookups) {
				t.Fatalf("received unexpected amount of challenges (expected: %d): %d", len(tc.lookups), n)
			}
		})
	}
}

func TestDeleteExercise(t *testing.T) {
	tt := []struct {
		name      string
		in        exer
		deleteTag store.Tag
		err       string
	}{
		{name: "Normal", in: exer{name: "Test", tags: []store.Tag{"tst"}}, deleteTag: "tst"},
		{name: "Unknown challenge", in: exer{name: "Test", tags: []store.Tag{"tst"}}, deleteTag: "not-test", err: "Unknown challenge tag: not-test"},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			es, err := store.NewChallengeStore([]store.ChallengeConfig{
				{
					Name: tc.in.name,
					Tags: tc.in.tags,
				}})
			if err != nil {
				t.Fatalf("received error when creating challenge store, but expected none: %s", err)
			}

			err = es.DeleteChallengeByTag(tc.deleteTag)
			if err != nil {
				if tc.err != "" {
					if tc.err != err.Error() {
						t.Fatalf("unexpected error (expected: \"%s\") when creating store: %s", tc.err, err)
					}

					return
				}

				t.Fatalf("unexpected error: %s", err)
			}

			if tc.err != "" {
				t.Fatalf("received no error, but expected error")
			}
		})
	}
}
