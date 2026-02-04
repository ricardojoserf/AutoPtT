# AutoPtT

Enumerate Kerberos tickets and perform Pass-The-Ticket (PtT) attacks interactively.


You can do this step by step or automatically with the different options:

- **`auto`** - Automated Pass-the-Ticket attack

- **`sessions`** - View all logon sessions. Similar to running `klist sessions`

- **`klist`** - List tickets in current session. Similar to running `klist`

- **`tickets`** - Enumerate tickets from all sessions. Similar to running `Rubeus.exe dump`

- **`export`** - Export a TGT given the LogonId. Similar to running `Rubeus.exe dump`

- **`ptt`** - Import a ticket file (.kirbi) given the file name. Similar to running `Rubeus.exe ptt`

<br>

-----------------------------------------------

## Examples

#### Automated Pass-The-Ticket

The tool enumerates the available TGTs, choose the index and the ticket gets dumped and imported to your session:

```
autoptt.exe auto
```

![img6](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/autoptt/Screenshot_6.png)


#### List logon sessions

```
autoptt.exe sessions
```

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/autoptt/Screenshot_1.png)


#### List tickets in current session

```
autoptt.exe klist
```

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/autoptt/Screenshot_2.png)


#### List tickets in all sessions

```
autoptt.exe tickets
```

![img3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/autoptt/Screenshot_3.png)


#### Export TGT given LogonId (in this case, 0x79fb3)

```
autoptt.exe export 0x79fb3
```

![img4](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/autoptt/Screenshot_4.png)


#### Import ticket file

```
autoptt.exe ptt 0x79fb3_Administrator.kirbi
```

![img5](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/autoptt/Screenshot_5.png)
