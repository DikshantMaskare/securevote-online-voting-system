# Security Policy

## Project status

SecureVote is an academic prototype. It must not be used for government,
public, corporate, or legally binding elections.

The included ledger is a local hash-linked file. It demonstrates tamper
detection, but it is not a decentralized blockchain and has no distributed
consensus, validators, or independent nodes.

## Never commit

- `secret.key` or a real `FERNET_KEY`
- `.env` files containing real values
- `voting.db` or any other voter database
- `chain_data.json` or ledger backups containing real votes
- SMTP credentials or application passwords

If any of these files are committed, deleting them in a later commit is not
enough. Remove them from Git history and rotate every exposed credential and
key.

## Known limitations

- SQLite and the JSON ledger are suitable only for a small single-instance
  demonstration.
- The app intentionally runs with one Gunicorn worker because its ledger is
  process-local and file-backed.
- Identity verification proves access to an email inbox, not legal voter
  eligibility.
- The application has not received an independent security audit or
  penetration test.
- Production deployments still need rate limiting, monitoring, backups,
  privacy controls, and an incident response process.

## Reporting a vulnerability

Open a GitHub issue without including credentials, personal data, working
attack payloads, or voter information. For sensitive reports, contact the
repository owner privately through their GitHub profile.
