## LKM Outbound Filter
It works on the Linux Kernel, using Netfilter to filter outbound traffic.

## Supported Filters
- **Signature Filter** (TCP, UDP)  
   Filters packets by inspecting payloads and matching specific signatures (DPI).

- **Port Filter** (TCP, UDP)  
   Filters traffic based on destination ports.

- **Netmask Filter**  (ALL)  
   Filters traffic by matching destination addresses against configured netmasks.

## Adding Filters
Filters can be dynamically added or removed by sending UDP packets to `127.0.0.1:209`

  
## Type Values
| Value | Operation                  |
|------|---------------------------|
| 0    | SET_PORT_FILTER           |
| 1    | REMOVE_PORT_FILTER        |
| 2    | SET_NETMASK_FILTER        |
| 3    | REMOVE_NETMASK_FILTER     |
| 4    | SET_SIGNATURE_FILTER      |
| 5    | REMOVE_SIGNATURE_FILTER   |

## Format
- **Port Filter**: `[type (1 byte)][protocol (1 bytes)][port (2 bytes)]`
- **Netmask Filter**: `[type (1 byte)][address (4 bytes)][mask (4 bytes)]`
- **Signature Filter**: `[type (1 byte)][signature (n bytes)]`

