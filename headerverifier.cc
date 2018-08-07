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


///include header files for referencing methods later
#include <click/config.h>
#include "headerverifier.hh"
#include <clicknet/ether.h>
#include <click/glue.hh>
#include <click/args.hh>
#include <click/straccum.hh>
#include <click/error.hh>
#include <click/standard/alignmentinfo.hh>

CLICK_DECLS

/*Exception handling in case of incorrect placement of element,
reasons enumerated in header file */
const char * const HeaderVerifier::reason_texts[NREASONS] = {

    "tiny packet", "too small for addresses", "bad hardware type/length",

    "bad protocol type/length"

};

//constructor
HeaderVerifier:: HeaderVerifier()
    : _reason_drops(0)
{
    _drops = 0;
}

///destructor
HeaderVerifier::~HeaderVerifier()
{
  delete[] _reason_drops;
}

///drop method  for dropping the packets detected as incorrect
Packet *
HeaderVerifier::drop(Reason reason, Packet *p)
{

  if (_drops == 0 || _verbose)

    click_chatter("ARP header check failed: %s", reason_texts[reason]);

  _drops++;



  if (_reason_drops)

    _reason_drops[reason]++;



  checked_output_push(1, p);

  return 0;

}

/*
Code design implemented here
DO NOT MODIFY, pointers set and offset hardcoded for ARP packet start 
byte position. _offset variable sets offset at which the method starts scanning
*/
Packet *
HeaderVerifier::simple_action(Packet *p)

{
  unsigned _offset = 14;
  const click_arp *ap = reinterpret_cast<const click_arp *>(p->data() + _offset);

  unsigned plen = p->length() - _offset;

  unsigned hlen;



  // cast to int so very large plen is interpreted as negative

  if ((int) plen < (int) sizeof(click_arp))

      return drop(MINISCULE_PACKET, p);



  hlen = (int) sizeof(click_arp) + 2*ap->ar_hln + 2*ap->ar_pln;
///Bad length drop method call
  if ((int) plen < (int) hlen)

      return drop(BAD_LENGTH, p);
/// wrong HRD drop method call
  else if (ap->ar_hrd == htons(ARPHRD_ETHER) && ap->ar_hln != 6)

      return drop(BAD_HRD, p);
/// for IPv4 and IPv6 if  length of protocol !=4 (IPv4), 16 (IPv6), drop 
  else if ((ap->ar_pro == htons(ETHERTYPE_IP) && ap->ar_pln != 4)

	   || (ap->ar_pro == htons(ETHERTYPE_IP6) && ap->ar_pln != 16))

      return drop(BAD_PRO, p);



  p->set_network_header((const unsigned char *) ap, hlen);

  return p;

}


///read method handler, unused
String
HeaderVerifier::read_handler(Element *e, void *)
{
  HeaderVerifier *c = reinterpret_cast<HeaderVerifier *>(e);

  StringAccum sa;

  for (int i = 0; i < NREASONS; i++)

      sa << c->_reason_drops[i] << '\t' << reason_texts[i] << '\n';

  return sa.take_string();

}
///add handlers method
void
HeaderVerifier::add_handlers()

{

    add_data_handlers("drops", Handler::OP_READ, &_drops);

    if (_reason_drops)

	add_read_handler("drop_details", read_handler, 1);

}



CLICK_ENDDECLS

EXPORT_ELEMENT(HeaderVerifier)
