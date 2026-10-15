package staticsite

// The ECR permissions the server needs. They live here, next to the code that
// uses them, because the IAM that grants them is derived from them
// (staticsite/awsiam builds its policy from these two lists and nothing
// else) and a guard test (ecrpermissions_test.go) fails when the server
// starts to call anything these lists do not cover.

// ECRAccountActions are the actions the server needs on every resource:
// ecr:GetAuthorizationToken supports no resource-level permission, so IAM
// wants "*".
func ECRAccountActions() []string {
	return []string{"ecr:GetAuthorizationToken"}
}

// ECRRepositoryActions are the actions the server needs on the repository the
// artifact lives in: the manifest (by tag or digest) and its layers, which the
// OCI registry endpoint maps to these. Nothing here writes.
func ECRRepositoryActions() []string {
	return []string{
		"ecr:BatchGetImage",
		"ecr:GetDownloadUrlForLayer",
		"ecr:BatchCheckLayerAvailability",
	}
}
