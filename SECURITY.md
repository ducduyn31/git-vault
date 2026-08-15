# Security Policy

git-vault protects secrets, so please **do not** report a vulnerability in a
public issue, pull request, or discussion.

## Reporting a vulnerability

Use [GitHub's private vulnerability reporting](https://github.com/ducduyn31/git-vault/security/advisories/new)
on this repository. It's private until an advisory is published.

Helpful things to include:

- What breaks, and what an attacker gets out of it (plaintext committed to
  history, a decrypt that should have failed, a key that leaks into logs).
- The git-vault version (`git-vault version`), OS, and key provider.
- Steps to reproduce, ideally against a scratch repo.

Expect an acknowledgement within a few days. Since this is a personal
project, fixes are best-effort — you'll get an honest timeline, not an SLA.
Please give the fix a chance to ship before disclosing publicly; credit in
the advisory is yours unless you'd rather stay anonymous.

## Supported versions

git-vault is pre-1.0. Only the latest release gets fixes — there are no
backports to older tags.

## Scope

In scope is anything that lets plaintext escape the working tree or lets
someone decrypt who shouldn't: the clean/smudge filter, the keyservice
plumbing, provider authorization, and key rotation or migration.

Out of scope are weaknesses in the key providers themselves (GCP KMS, AWS
KMS, Azure Key Vault, HashiCorp Vault) and in [sops](https://github.com/getsops/sops)
— report those upstream. Also out of scope: a misconfigured repo that never
registered the filter, and anything that requires an attacker to already have
read access to your working tree.
