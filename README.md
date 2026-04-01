# CloudProwl

Enumerate Microsoft service access from a refresh token.

CloudProwl takes a refresh token and uses token exchange to discover which Microsoft services the user has access to.

<img width="1380" height="765" alt="image" src="https://github.com/user-attachments/assets/d50ce4f7-ccdd-480e-8bca-7e911956bc77" />

## Services Enumerated

| Service | What It Probes |
|---|---|
| Microsoft Graph | User identity, tenant ID |
| Azure Resource Manager | Subscriptions, resource access |
| Power Platform (BAP) | Environments and environment types |
| Dataverse | Canvas apps, model-driven apps, unmanaged solutions per environment |
| Power Apps | Published applications |
| Microsoft Flow | Power Automate environments |
| Azure DevOps | Organizations |
| Microsoft Teams | Tenant membership and license status |
| Outlook / Exchange Online | Mailbox access |

## Install

```bash
git clone https://github.com/pwnedlabs/cloudprowl.git
cd cloudprowl
pip install roadtx
```

If `roadtx` is not installed, CloudProwl will attempt to install it automatically on first run.

## Usage

```bash
python3 cloudprowl.py <refresh_token>
```

## Requirements

- Python 3.8+
- [roadtx](https://github.com/dirkjanm/ROADtools) (ROADtools token exchange utility)

## License

MIT
