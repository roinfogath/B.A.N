fingerprints data for http-default-accounts.nse

replace http-default-accounts-fingerprints.lua under /usr/share/nmap/nselib/data/  

run: nmap -p80,81,8080,8081,8082 -Pn --open --script=http-default-accounts.nse target(s)

for better security change your default router/camera password
 
aded new signatures 
Netgear CG3300CMR,
        WGR614
        
ZyXel   P-870HW,
        P-660HW-D1
        
Net-Lynx

HUAWEI  SmartAX MT882,
        EchoLife HG520b 

ASUS    RT-G32(need more tests),
        RT-N56U,
        RT-N10.B1,
        RT-N12E,
        RT-N10E,
        RT-N12C1,
        WL530g-V2,
        WL500gP,
        RT-N10,
        WL520gc,
        WL520g,
        WL500gpv2,
        RT-N11,
        RT-N10LX,
        WL-500gP V2,
        RT-N66U,
        RT-N12+,
        RT-AC56U,
        RT-N12D1,
        RT-N12LX,
        RT-AC66U,
        
D-Link  DI-524,
        DI-524UP,
        DI-804HV,      
        
TP-LINK  WR740N,
         WR1043ND,
         WR841N,
         WA5210G
         WDR3600, 
         TL-WR720N, 
         TD-W8951ND, 
         TL-WR841HP,  

TRENDNET TEW-432BRP

SERIOUX SRX-WR150WH

LevelOne WBR-6003

UMTS UR5i   

Broadband Router 

U.S. Robotics 

EVOLVE Router Wireless

TRENDnet IP Camera TV-IP551WI 

ip camera-DVR WEB 

more to come  
