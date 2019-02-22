[![CircleCI](https://circleci.com/gh/dollarshaveclub/acyl.svg?style=svg&circle-token=e02d60ca20107ad11a982978184233225c909541)](https://circleci.com/gh/dollarshaveclub/acyl)
[![Docker Repository on Quay](https://quay.io/repository/dollarshaveclub/acyl/status?token=7750d7c3-5f1f-4d90-82c4-6b32dbd591a1 "Docker Repository on Quay")](https://quay.io/repository/dollarshaveclub/acyl)


# Acyl
*Testing Environments On Demand*

Acyl is a server and CLI utility for creating dynamic testing environments on demand in Kubernetes, triggered by GitHub Pull Requests.

Environments are defined by `acyl.yml` in your source code repository, and consist of one or more Helm Charts that are installed into a new Kubernetes namespace that is created on demand and torn down when you're finished. Environment lifecycles are tied to Pull Requests: a new environment is created when you open a PR, it is updated as you push additional commits to the PR, and finally it is destroyed when the PR is closed or merged, automatically.

Acyl includes features to make team collaboration and environment configuration easier for multiple teams working on complex application stacks, allowing teams to maintain separate isolated testing environments but share revisions of in-progress code when needed.

Acyl has been used in various forms as part of the core Dollar Shave Club software delivery pipeline since 2016, as described in a recent [blog post](https://engineering.dollarshaveclub.com/qa-environments-on-demand-with-kubernetes-5a571b4e273c).

## Configuration

Environments are defined by `acyl.yml`, which declaritively describes the required Helm Charts along with their release value configuration and the dependency relationships among them. The config file can be thought of as a "Helm compose", analagous to Docker Compose except using Helm Charts instead of individual containers. Acyl uses [Metahelm](https://github.com/dollarshaveclub/metahelm) to construct a dependency graph of the environment charts and installs them in optimal reverse-dependency order.

An `acyl.yml` in one application repository can reference `acyl.yml` files in other repositories, and those applications (and their dependencies) will be transitively included in the environment. In this way complex application stacks maintained by different teams can share testing environment configuration.

## Architecture

Acyl is a complex system with several components:

![Architecture](doc/acyl_architecture.png?raw=true)

- Acyl: This is the server application which listens for GitHub webhook events and performs operations to create, update or destroy environments within your Kubernetes cluster. The server is intended to run within the same cluster, with ClusterAdmin permissions. The Acyl binary also can be used as a local CLI utility for local environment development and debugging.
- Postgres: This is the primary datastore for Acyl.
- Consul: This is used for event concurrency control/locking.
- Furan: This is used to build and push application Docker images on demand.

## Quickstart

TODO

## Further Reading
- User Guide
- acyl.yml v2 Specification

