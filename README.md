# @gibme/snmp

A simple async/await SNMP helper/wrapper built on top of [snmp-native](https://github.com/calmh/node-snmp-native).

## Requirements

- Node.js >= 22

## Installation

```bash
npm install @gibme/snmp
```

```bash
yarn add @gibme/snmp
```

## Usage

The package supports both **static methods** (shared session) and **instance methods** (dedicated session).

### Static Methods

Use static methods for simple operations that share a single underlying SNMP session:

```typescript
import SNMP from '@gibme/snmp';

const options: SNMP.Options = {
    host: '192.168.1.1',
    community: 'public'
};

// Get a single OID
const result = await SNMP.get(options, '.1.3.6.1.2.1.1.1.0');

// Get multiple OIDs
const results = await SNMP.getAll(options, [
    '.1.3.6.1.2.1.1.1.0',
    '.1.3.6.1.2.1.1.5.0'
]);

// Get next OID in the tree
const next = await SNMP.getNext(options, '.1.3.6.1.2.1.1');

// Walk a subtree
const subtree = await SNMP.getSubtree(options, ['.1.3.6.1.2.1.1']);

// Set a value
await SNMP.set(options, '.1.3.6.1.2.1.1.5.0', SNMP.DataType.OctetString, 'new-hostname');

// Close the shared session when done
SNMP.close();
```

### Instance Methods

Create instances when you need independent SNMP sessions:

```typescript
import SNMP from '@gibme/snmp';

const snmp = new SNMP();

const result = await snmp.get({
    host: '192.168.1.1',
    community: 'public'
}, '.1.3.6.1.2.1.1.1.0');

// Close the instance session when done
snmp.close();
```

## API

### Methods

All methods are available as both static and instance methods.

| Method | Description |
|---|---|
| `get(options, oid)` | Perform a GetRequest for a single OID |
| `getAll(options, oids)` | Perform GetRequests for multiple OIDs |
| `getNext(options, oid)` | Perform a GetNextRequest |
| `getSubtree(options, oids)` | Walk a subtree via repeated GetNextRequests |
| `set(options, oid, type?, value?)` | Perform a SetRequest |
| `close()` | Close the underlying SNMP session |

### Types

#### `SNMP.Options`

Connection options passed to the underlying snmp-native session. Common fields:

| Field | Type | Description |
|---|---|---|
| `host` | `string` | SNMP agent hostname or IP address |
| `community` | `string` | SNMP community string |
| `port` | `number` | UDP port (default: `161`) |
| `version` | `SNMP.Versions` | Protocol version (default: `SNMPv2c`) |

#### `SNMP.OID`

A string type that must start with a dot (e.g., `.1.3.6.1.2.1.1.1.0`).

#### `SNMP.Response<Type>`

A `Record<OID, Type | undefined>` mapping each OID to its result.

#### `SNMP.VarBind`

An SNMP variable binding containing the OID and its value.

#### `SNMP.DataType`

ASN.1 data type constants: `Integer`, `OctetString`, `Null`, `ObjectIdentifier`, `IPAddress`, `Counter`, `Gauge`, `TimeTicks`, `Opaque`, `NsapAddress`, `Counter64`, and others.

#### `SNMP.Versions`

Protocol version constants: `SNMPv1` and `SNMPv2c`.

## Documentation

Full API documentation is available at [https://gibme-npm.github.io/snmp/](https://gibme-npm.github.io/snmp/)

## License

MIT
