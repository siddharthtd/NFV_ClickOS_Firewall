
#ifndef CLICK_ARPMITIGATE_HH
#define CLICK_ARPMITIGATE_HH
#include <click/element.hh>
CLICK_DECLS

class ARPMitigate : public Element { public:
    
    ARPMitigate() CLICK_COLD;
    ~ARPMitigate() CLICK_COLD;
    
    const char *class_name() const        { return "ARPMitigate"; }
    const char *port_count() const        { return PORTS_1_1; }
    
    int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
    int initialize(ErrorHandler *) CLICK_COLD;
    void cleanup(CleanupStage) CLICK_COLD;
    void add_handlers() CLICK_COLD;
    
    Packet *simple_action(Packet *);
    
private:
    
    
#if CLICK_USERLEVEL
    String _outfilename;
    FILE *_outfile;
#endif
    ErrorHandler *_errh;
    
};

CLICK_ENDDECLS
#endif

