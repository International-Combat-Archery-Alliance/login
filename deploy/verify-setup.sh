#!/bin/bash
# Yes/no readiness check for the login GitHub deploy role.
# Run from CloudShell after the setup in deploy/README.md:
#   bash deploy/verify-setup.sh
# Exits 0 only if everything is in place.
ACCOUNT=197461532156
ROLE=login-github-deploy
POLICY=sam-deploy
BUCKET=aws-sam-cli-managed-default-samclisourcebucket-dvijzdyhur0e
ECR_REPO=logind56b6998/icaalogina6e895derepo
export AWS_REGION=us-east-1

fail=0
ok() { echo "PASS: $1"; }
bad() { echo "FAIL: $1"; fail=1; }

[ "$(aws sts get-caller-identity --query Account --output text 2>/dev/null)" = "$ACCOUNT" ] \
  && ok "signed in to account $ACCOUNT" \
  || bad "not signed in to account $ACCOUNT"

aws iam list-open-id-connect-providers --query OpenIDConnectProviderList --output text 2>/dev/null \
  | grep -q token.actions.githubusercontent.com \
  && ok "GitHub OIDC provider exists" \
  || bad "GitHub OIDC provider missing"

trust="$(aws iam get-role --role-name "$ROLE" --query Role.AssumeRolePolicyDocument --output json 2>/dev/null)"
if [ -z "$trust" ]; then
  bad "role $ROLE missing"
else
  ok "role $ROLE exists"
  echo "$trust" | grep -q sts:AssumeRoleWithWebIdentity \
    && ok "trust allows AssumeRoleWithWebIdentity" \
    || bad "trust missing AssumeRoleWithWebIdentity"
  echo "$trust" | grep -q "repo:International-Combat-Archery-Alliance/login:ref:refs/heads/main" \
    && ok "trust scoped to login main branch" \
    || bad "trust scoped to wrong repo/branch"
fi

sids="$(aws iam get-role-policy --role-name "$ROLE" --policy-name "$POLICY" \
  --query 'PolicyDocument.Statement[].Sid' --output text 2>/dev/null)"
expected="ApiGateway CloudFormationReads CloudFormationStack EcrAuth EcrImagePush EcrPublicAuth ExecutionRole LambdaFunctions LogGroup LogGroupReads SamArtifactsBucket SamTransform"
if [ "$(echo "$sids" | tr '\t\n' ' ' | tr ' ' '\n' | sort | tr '\n' ' ' | xargs)" = "$expected" ]; then
  ok "inline policy $POLICY has all 9 statements"
else
  bad "inline policy $POLICY missing or has wrong statements (got: $sids)"
fi

aws s3api head-bucket --bucket "$BUCKET" 2>/dev/null \
  && ok "SAM artifacts bucket $BUCKET exists" \
  || bad "SAM artifacts bucket $BUCKET missing"

aws ecr describe-repositories --repository-names "$ECR_REPO" --query 'repositories[0].repositoryUri' --output text 2>/dev/null \
  | grep -q . \
  && ok "ECR repo $ECR_REPO exists" \
  || bad "ECR repo $ECR_REPO missing"

echo
if [ "$fail" -eq 0 ]; then
  echo "ALL CHECKS PASSED - safe to merge, first deploy will run on merge to main."
else
  echo "SETUP INCOMPLETE - fix the FAIL lines above, then re-run."
fi
exit "$fail"
