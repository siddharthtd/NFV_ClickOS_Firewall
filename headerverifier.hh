#ifndef CLICK_HEADERVERIFIER_HH
#define CLICK_HEADERVERIFIER_HH
#include <click/element.hh>
#include <click/atomic.hh>
CLICK_DECLS
///decleration
class HeaderVerifier : public Element { public:
///constructor and destructor decleration
  HeaderVerifier() CLICK_COLD;
  ~HeaderVerifier() CLICK_COLD;
//return class name, port count and processing type (push, pull or agnostic)
    const char *class_name() const		{ return "HeaderVerifier"; }
    const char *port_count() const		{ return PORTS_1_1X2; }
    const char *processing() const		{ return PROCESSING_A_AH; }

  void add_handlers() CLICK_COLD;
///methods declared
  Packet *simple_action(Packet *);

 private:
/*determines the start of packet, hardcoded as 14 in the 
headerverifier.cc file, for ARP packets. */
  unsigned _offset;

  bool _verbose : 1;

  atomic_uint32_t _drops;
  atomic_uint32_t *_reason_drops;
/// Reason of dropping packet, called from the drop method
  enum Reason {
    MINISCULE_PACKET,
    BAD_LENGTH,
    BAD_HRD,
    BAD_PRO,
    NREASONS
  };
  static const char * const reason_texts[NREASONS];

  Packet *drop(Reason, Packet *);
  static String read_handler(Element *, void *) CLICK_COLD;

};

CLICK_ENDDECLS
#endif
