# Github Workflows

## [Kgateway Conformance Tests](./regression-tests.yaml)
Conformance tests a pinned version of the [Kubernetes Gateway API Conformance suite](https://github.com/kubernetes-sigs/gateway-api/blob/main/conformance/conformance_test.go).

### Draft Pull Requests
This Github Action will not run by default on a Draft Pull Request. After a Pull Request is marked as `Ready for Review`
it will trigger the action to run.

## [Kubernetes End-to-End Tests](./pr-kubernetes-tests.yaml)
Regression tests run the suite of [Kubernetes End-To-End Tests](https://github.com/kgateway-dev/kgateway/tree/main/test/kubernetes/e2e).

### Draft Pull Requests
This Github Action will not run by default on a Draft Pull Request. After a Pull Request is marked as `Ready for Review`
it will trigger the action to run.

## [Lint Helm Charts](./lint-helm.yaml)
Perform linting on project [Helm Charts](../../install/helm/README.md).

## [WIP Labeler](./wip-labeler.yaml)
Automatically manages the "work in progress" label on pull requests based on their draft status:

- **Adds "work in progress" label** when a PR is opened as a draft or converted to draft
- **Removes "work in progress" label** when a draft PR is marked as ready for review

This workflow helps maintain consistency in labeling and integrates with the existing labeler workflow that blocks merging of PRs with the "work in progress" label.

### Triggers
- `opened`: When a new PR is created
- `reopened`: When a closed PR is reopened  
- `ready_for_review`: When a draft PR is marked as ready for review
- `converted_to_draft`: When a ready PR is converted back to draft

## Future Work
It would be great to add support for issue comment directives. This would mean that commenting `/sig-ci` would signal CI to run, or `/skip-ci` would auto-succeed CI.

This was attempted, and the challenge is that Github workflows were kicked off, but not associated with the PR that contained the comment. Therefore, the PR status never changed, even if the job that was kicked off passed all the tests.
