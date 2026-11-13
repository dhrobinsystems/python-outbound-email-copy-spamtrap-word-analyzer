# ⚠️ Disclaimer & Liability Limitation

Use at your own risk. The code, rules and scripts provided in this repository (`outbound-email-copy-spamtrap-word-analyzer`) are for educational and architectural demonstration purposes.

- **No Liability:** The author (Revenue Infrastructure Architect, dhRobin Systems) and dhRobin Systems assume no responsibility or liability for any direct, indirect, incidental, or consequential damages resulting from the use, misuse, or deployment of this tool.
- **No Warranty:** All software, rule dictionaries and Python modules are provided "AS IS" without warranty of any kind, express or implied, including but not limited to merchantability, fitness for a particular purpose, or non-infringement.
- **Production Testing Required:** Always validate sequences with seed or inbox-placement tests on a warmed-up, isolated sending domain before launching to live prospects or connecting production outbound accounts.
- **Third-Party APIs & Compliance:** Users are solely responsible for complying with the terms of service, sending limits, data privacy regulations (GDPR/CCPA), anti-spam laws (e.g. CAN-SPAM, CASL, PECR), and security policies of Smartlead, Instantly and any connected services, including honouring every unsubscribe request and reviewing every sequence before it is sent.

## Deliverability and filtering

This tool analyses email **content** only. Whether a message reaches the inbox also depends on factors it cannot see or control, including sender and domain reputation, SPF / DKIM / DMARC authentication, domain age and warm-up, sending volume and cadence, list quality, recipient engagement, and the proprietary, frequently changing filters of each mailbox provider.

Accordingly:

- A low **Spam Risk Score**, a PASS status or the absence of findings is **not** a guarantee of inbox placement, and a high score is not proof that a message will be filtered.
- The author and dhRobin Systems accept **no liability** for email deliverability failures, messages routed to spam or junk folders, domain or IP **blacklisting**, spam-filter or firewall actions, sending-account warnings, suspensions or terminations, or any loss of revenue, pipeline, reputation or data arising from them.
- The author and dhRobin Systems accept **no liability** for risks arising from third-party CRM or outbound platforms (including but not limited to Smartlead, Instantly and HubSpot): their availability, API behaviour, merge-tag rendering, tracking, unsubscribe handling, data processing or policy enforcement.

## Regulatory compliance

The person or organisation that deploys this tool and sends email (**the deployer**) holds **sole responsibility** for compliance with all laws and regulations that apply to outbound email, including but not limited to:

- **CAN-SPAM Act** (United States): accurate header and subject information, identification of commercial messages, a valid physical postal address, a working opt-out mechanism, and honouring opt-outs promptly;
- **GDPR** and **UK GDPR**: a lawful basis for processing personal data (for example, documented legitimate interest), transparency, data-subject rights, and data minimisation;
- **PECR** (United Kingdom), **CASL** (Canada), **CCPA/CPRA** (California) and any other local electronic-marketing, privacy or consumer-protection law.

The `COMPLIANCE_NO_OPT_OUT` check is a convenience heuristic. It is **not legal advice** and does not determine whether a message is lawful. Consult qualified legal counsel for compliance decisions.

## Data handling

The analyzer runs locally, makes no network calls and stores nothing. Users are responsible for the copy, lead data and any reports they create with it, and for keeping credentials, client names and personal data out of shared repositories and logs.

## Liability limitation

> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. THE DEPLOYER ASSUMES FULL RESPONSIBILITY FOR EMAIL DELIVERABILITY, SENDER REPUTATION, PLATFORM ACCOUNT STANDING, AND COMPLIANCE WITH OUTBOUND EMAIL REGULATIONS WHEN USING THIS SOFTWARE.

## License

Released under the MIT License. Copyright (c) 2026 DH Robin (dhRobin Systems). See [LICENSE](LICENSE).
