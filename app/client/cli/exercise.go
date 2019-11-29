// Copyright (c) 2018-2019 Aalborg University
// Use of this source code is governed by a GPLv3
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	pb "github.com/aau-network-security/haaukins/daemon/proto"
	"github.com/spf13/cobra"
)

func (c *Client) CmdChallenge() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "challenge",
		Short: "Actions to perform on exercises",
		Args:  cobra.MinimumNArgs(1),
	}

	cmd.AddCommand(
		c.CmdChallengeList(),
		c.CmdChallengeReset(),
		c.CmdUpdateChallengeFile(),
	)

	return cmd
}

func (c *Client) CmdChallenges() *cobra.Command {
	return &cobra.Command{
		Use:     "challenges",
		Short:   "List challenges",
		Example: `hkn challenge list`,
		Run: func(cmd *cobra.Command, args []string) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			r, err := c.rpcClient.ListChallenges(ctx, &pb.Empty{})
			if err != nil {
				PrintError(err)
				return
			}

			f := formatter{
				header: []string{"NAME", "TAGS", "# DOCKER IMAGES", "# VBOX IMAGES"},
				fields: []string{"Name", "Tags", "DockerImageCount", "VboxImageCount"},
			}

			var elements []formatElement
			for _, e := range r.Challenges {
				elements = append(elements, struct {
					Name             string
					Tags             string
					DockerImageCount int32
					VboxImageCount   int32
				}{
					Name:             e.Name,
					Tags:             strings.Join(e.Tags, ","),
					DockerImageCount: e.DockerImageCount,
					VboxImageCount:   e.VboxImageCount,
				})
			}

			table, err := f.AsTable(elements)
			if err != nil {
				PrintError(UnableCreateEListErr)
				return
			}
			fmt.Printf(table)
		},
	}
}

func (c *Client) CmdChallengeList() *cobra.Command {
	cmd := *c.CmdChallenges()
	cmd.Use = "ls"
	cmd.Aliases = []string{"ls", "list"}
	return &cmd
}
func (c *Client) CmdUpdateChallengeFile() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "update [path of challenges file]",
		Short:   "Updates challenges file",
		Example: "hkn update challenges.yml",
		Args:    cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
			defer cancel()
			resp, err := c.rpcClient.UpdateChallengesFile(ctx, &pb.Empty{})
			if err != nil {
				PrintError(err)
			}
			fmt.Println(resp.Msg)
		},
	}
	return cmd
}

func (c *Client) CmdChallengeReset() *cobra.Command {
	var (
		evTag   string
		teamIds []string
		teams   []*pb.Team
	)

	cmd := &cobra.Command{
		Use:     "reset [challenge tag]",
		Short:   "Reset exercises",
		Long:    "Reset exercises, use -t for specifying certain teams only.",
		Example: `hkn reset sql -e esboot -t d11eb89b`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			for _, t := range teamIds {
				teams = append(teams, &pb.Team{Id: t})
			}

			chTag := args[0]
			stream, err := c.rpcClient.ResetChallenge(ctx, &pb.ResetChallengeRequest{
				ChallengeTag: chTag,
				EventTag:     evTag,
				Teams:        teams,
			})

			if err != nil {
				PrintError(err)
				return
			}

			for {
				msg, err := stream.Recv()
				if err == io.EOF {
					break
				}

				if err != nil {
					log.Fatalf(err.Error())
				}

				fmt.Printf("[%s] %s\n", msg.Status, msg.TeamId)
			}
		},
	}

	cmd.Flags().StringVarP(&evTag, "evtag", "e", "", "the event name")
	cmd.Flags().StringSliceVarP(&teamIds, "teams", "t", nil, "list of team ids for which to reset the challenge")
	cmd.MarkFlagRequired("evtag")

	return cmd
}
