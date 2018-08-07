src :: FromDevice
dest :: ToDevice

c :: Classifier(
        12/0806 20/0002,  ///if arp reply
        -);

src ->c
c[0] ->HeaderVerifier()->ARPMitigate()->dest;
c[1] ->Discard;

