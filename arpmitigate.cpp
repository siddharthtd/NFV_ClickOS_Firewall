/* Publishers:
    Deepak Devaru Joshi
    Siddharth Thakurdesai

Date: 05/10/2018



/* This code is solely for the purpose of education.
 The code was designed after studying various click elemnts and this code derives keywords from other elements defined in clickos directories.
 The click elements that were used while designing the code are as follows and their directories from where they are derived are as mentioned below:
 checkipaddress.cc -> /home/ubuntu/cmpe210_clickos_setup/clickos/ip/checkipaddress.cc
 ipprint.cc -> /home/ubuntu/cmpe210_clickos_setuo/clickos/ip/ipprint.hh
 arpprint.cc-> /home/ubuntu/cmpe210_clickos_setup/click/ethernet/arpprint.cc
 
 github link for click elements : https://github.com/kohler/click
 github link for documentations of click: https://github.com/kohler/click/wiki
 */

///////************** THE CODE BEGINS FROM HERE ! **************************************************************

#include <click/config.h>
#include "arpmitigate.hh"
#include <click/glue.hh>
#include <click/args.hh>
#include <click/error.hh>
#include <click/straccum.hh>
#include <click/packet_anno.hh>
#include <click/router.hh>
#include <click/nameinfo.hh>

#include <click/etheraddress.hh>
#include <clicknet/ether.h>

#if CLICK_USERLEVEL
# include <stdio.h>
#endif

CLICK_DECLS


ARPMitigate::ARPMitigate()

{
#if CLICK_USERLEVEL
    _outfile = 0;
#endif
}

ARPMitigate::~ARPMitigate()
{
}

///configuring ARPMItigate for user-level
int
ARPMitigate::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String channel;
    
    if (Args(conf, this, errh)
        
#if CLICK_USERLEVEL
        .read("OUTFILE", FilenameArg(), _outfilename)
#endif
        .complete() < 0)
        return -1;
    
    _errh = router()->chatter_channel(channel);
    return 0;
}

///Initialising Error Handler
int
ARPMitigate::initialize(ErrorHandler *errh)
{
#if CLICK_USERLEVEL
    if (_outfilename) {
        _outfile = fopen(_outfilename.c_str(), "wb");
        if (!_outfile)
            return errh->error("%s: %s", _outfilename.c_str(), strerror(errno));
    }
#else
    (void) errh;
#endif
    return 0;
}

///Clean-up if userlevel
void
ARPMitigate::cleanup(CleanupStage)
{
#if CLICK_USERLEVEL
    if (_outfile)
        fclose(_outfile);
    _outfile = 0;
#endif
}


Packet *
ARPMitigate::simple_action(Packet *pkt)
{
    StringAccum ba;
    
    ///////////////////////////////////////////////////////////////////////////////////////////////
    ///Predefining source ips (scrip_stored) that have valid map with mac address(srcmac_stored)///
    //////////////////////////////////////////////////////////////////////////////////////////////
    String srcip_stored[5]= {"10.250.195.101","10.250.195.102","10.250.195.103","10.250.195.104","10.250.195.105","10.250.195.106"};
    String srcmac_stored[5]={"B4-8B-19-43-3F-E3","68-A8-6D-BB-91-E5","3C-2E-FF-41-5E-CC","BC-54-36-E3-4C-B9","C4-8E-8F-07-0C-C7","4C-32-75-99-E3-A5"};
    
    printf("entering simple action module\n");
    printf("\n");
    
    ///To check if the length of the packet is less than the size of arp header. If yes print truncated arp and exit
    if (pkt->network_length() < (int) sizeof(click_arp))
        ba << "truncated-arp (" << pkt->network_length() << ")";
    
    else {
        
       ///create a pointer arp pointing to network header of the packet
        const click_ether_arp *arp = (const click_ether_arp *) pkt->network_header();
        
        
        const unsigned char *sha = (const unsigned char *)arp->arp_sha; /// source hardware address
        const unsigned char *spa = (const unsigned char *)arp->arp_spa;///source protocol address
        const unsigned char *tha = (const unsigned char *)arp->arp_tha; ///source target hardware address
        const unsigned char *tpa = (const unsigned char *)arp->arp_tpa; ///target protocol address
        
       
        ba << "Sender mac address : "<<EtherAddress(sha) << "\n";
        ba << "Sender ip address : " << IPAddress(spa) << "\n";
        ba << "Destination mac address : " << EtherAddress(tha)<<"\n";
        ba << "Destination ip address :  " << IPAddress(tpa)<<"\n";
        
        
       
        
        
        
        /////If incoming IP address and MAC address maps to stored IP Address and MAC address, return valid packet , else drop the packet
        
        for (int i = 0; i<5; i++) {
         
            if(IPAddress(spa) == srcip_stored[i] && EtherAddress(sha)!=srcmac_stored[i]){
                printf("INVALID MAPING OF MAC & IP ..POSSILE SPOOFING !! DROPING THE PACKET\n");
                printf("\n");
                pkt->kill(); ///Drop the packet
                return 0;
            }
            else{
                printf("Valid address\n");
                printf("\n");
                return pkt;
            }
        }
        
    }
    
    
#if CLICK_USERLEVEL
    if (_outfile) {
        ba << '\n';
        ignore_result(fwrite(sa.data(), 1, ba.length(), _outfile));
    } else
#endif
        _errh->message("%s", ba.c_str());
    
    return pkt;
}


/*void
 ARPMitigator::add_handlers()
 {
 add_data_handlers("active", Handler::OP_READ | Handler::OP_WRITE, &_active);
 }
 */
CLICK_ENDDECLS
EXPORT_ELEMENT(ARPMitigate)

