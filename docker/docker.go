package docker

import (
	"context"
	"errors"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/strslice"
	"github.com/docker/docker/client"
	"io"
	"log"
	"os"
	"strings"
)

// ContainerManager is a wrapper over Docker SDK to easily manage docker container status
// inside analysis pipeline
type ContainerManager struct {
}

func (cm *ContainerManager) RunContainer(containerName string, imageName string) (*types.Container, error) {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}

	if strings.Contains(imageName, "/") {
		out, err := cli.ImagePull(ctx, imageName, types.ImagePullOptions{})
		if err != nil {
			return nil, err
		}
		defer out.Close()
		io.Copy(os.Stdout, out)
	}

	resp, err := cli.ContainerCreate(ctx, &container.Config{
		Image:        imageName,
		Hostname:     "localhost",
		Labels:       map[string]string{"name": containerName},
		AttachStderr: true,
		AttachStdin:  true,
		AttachStdout: true,
		Entrypoint:   strslice.StrSlice{"tail", "-f", "/dev/null"},
	}, nil, nil, nil, containerName)
	if err != nil {
		return nil, err
	}
	if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		return nil, err
	}
	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{
		All: true,
	})
	if err != nil {
		return nil, err
	}
	for _, item := range containers {
		if item.ID == resp.ID {
			return &item, nil
		}
	}
	return nil, errors.New("container failed to start")
}

func (cm *ContainerManager) DeleteContainer() {
}

// StopAllContainers stops all existing containers in the server
func (cm *ContainerManager) StopAllContainers() error {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}
	defer cli.Close()

	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{
		All: true,
	})
	if err != nil {
		return err
	}

	for _, item := range containers {
		fmt.Print("Stopping container ", item.ID[:10], "... ")
		if err := cli.ContainerStop(ctx, item.ID, nil); err != nil {
			log.Println(err)
		}
		fmt.Println("Success")
	}
	return nil
}

// RemoveAllContainers removes all existing containers in the server
func (cm *ContainerManager) RemoveAllContainers() error {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}
	defer cli.Close()

	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{
		All: true,
	})
	if err != nil {
		return err
	}

	for _, item := range containers {
		fmt.Print("Removing container ", item.ID[:10], "... ")
		if err := cli.ContainerRemove(ctx, item.ID, types.ContainerRemoveOptions{
			Force: true,
		}); err != nil {
			log.Println(err)
		}
		fmt.Println("Success")
	}
	return nil
}

func (cm *ContainerManager) IsContainerAlive(name string) (*types.Container, error) {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}
	defer cli.Close()

	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{
		All: true,
	})
	if err != nil {
		return nil, err
	}

	for _, item := range containers {
		containerName := item.Names[0]
		if containerName[0] == '/' {
			containerName = containerName[1:]
		}
		if containerName == name {
			return &item, nil
		}
	}
	return nil, errors.New("container not found")
}
