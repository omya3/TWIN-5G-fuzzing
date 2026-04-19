# Multi-Message-Type Campaign Runbook

## Why this file exists

We already proved one important live experiment:

- if the first NAS message type is changed from `Registration request` to `Identity response`
- the malformed NAS reaches `Open5GS`
- and `Open5GS` rejects it with `Invalid 5GMM message type [92]`

Now the next sensible question is:

`What happens if we try other first NAS message types too?`

This runbook explains how to do that in a repeatable way.

## 1. What we already automated locally

We created:

- [generate_first_nas_message_type_campaign.sh](/Users/sailor_omkar/Documents/Mtech_RA_Courses/sem_4/TWIN/scripts/generate_first_nas_message_type_campaign.sh)

This script generates several JSON mutation cases from the real captured trace:

- `msgtype-41-registration-request.json`
- `msgtype-56-authentication-request.json`
- `msgtype-57-authentication-response.json`
- `msgtype-5c-identity-response.json`
- `msgtype-5d-security-mode-command.json`

These files live under:

- [first_nas_type_campaign](/Users/sailor_omkar/Documents/Mtech_RA_Courses/sem_4/TWIN/remote_traces/first_nas_type_campaign)

## 2. What is still manual on the remote machine

Right now, the remote UE patch is hardcoded to:

- change `0x41`
- into `0x5c`

That is fine for one experiment, but not ideal for a campaign.

For repeated testing, the better version is:

- read the target message type code from an environment variable

In simple words:

- today: the code always mutates to `0x5c`
- better version: the code mutates to whatever value we pass in

## 3. The simple goal

We want the remote UE patch to work like this:

- `TWIN_MUTATE_INITIAL_REG=1`
- `TWIN_MUTATE_INITIAL_REG_MSGTYPE=0x56`

Then the first live NAS message gets changed to `0x56`.

If we run it again with:

- `TWIN_MUTATE_INITIAL_REG_MSGTYPE=0x57`

then it changes to `0x57`, and so on.

## 4. Why this matters

Without this change, testing five message types means:

- editing code
- rebuilding
- rerunning
- editing again

With the environment-variable version, testing five message types means:

- one code change
- one rebuild
- then only changing the launch command each time

That is much closer to an experiment harness.

## 5. Recommended campaign order

These are the first message types we should test as the first NAS message:

1. `0x5c` `Identity response`
2. `0x56` `Authentication request`
3. `0x57` `Authentication response`
4. `0x5d` `Security mode command`

We do not need to test `0x41` first because that is just the normal baseline.

## 6. What to record for each run

For every message type, record:

- message type code
- label
- whether UE mutation fired
- whether gNB forwarded successfully
- whether AMF received `InitialUEMessage`
- AMF outcome
- whether UE retried / timed out

## 7. Suggested results table format

| Code | Label | UE mutation fired | gNB forwarded | AMF received `InitialUEMessage` | AMF result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `0x5c` | `Identity response` | yes | yes | yes | `Invalid 5GMM message type [92]` | already verified |
| `0x56` | `Authentication request` | pending | pending | pending | pending | next |
| `0x57` | `Authentication response` | pending | pending | pending | pending | next |
| `0x5d` | `Security mode command` | pending | pending | pending | pending | next |

## 8. What “good progress” looks like

For this campaign, “success” does not mean registration succeeds.

It means:

- the malformed first NAS reaches the AMF
- the AMF reacts in some observable way

Examples of valid outcomes:

- clean rejection
- parser error
- protocol-state error
- context cleanup
- timeout

All of these are useful observations.

## 9. Next engineering improvement

The next engineering step is:

- parameterize the UE mutation byte with `TWIN_MUTATE_INITIAL_REG_MSGTYPE`

After that, we can loop through several first message types with only launch-command changes.

## 10. Very simple summary

In noob language:

- we already tested one broken first message
- now we want to test several broken first messages
- the smart way is to make the mutation byte configurable
- then each experiment becomes just:
  - start gNB
  - start AMF log
  - launch UE with a different message type code
  - collect the result
