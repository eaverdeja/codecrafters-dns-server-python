# Actual
b"hy\x81\x00\x00\x02\x00\x02\x00\x00\x00\x00\x03abc\x11longassdomainname\x03com\x00\x00\x01\x00\x01\x03abc\x11longassdomainname\x03com\x00\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x7f\x00\x00\x01\x03def\x00\x00\x01\x00\x01"

# Expected
b"hy\x81\x00\x00\x02\x00\x02\x00\x00\x00\x00\x03abc\x11longassdomainname\x03com\x00\x00\x01\x00\x01\x03def\x00\x00\x01\x00\x01\x03abc\x11longassdomainname\x03com\x00\x00\x01\x00\x01\x00\x00\x00<\x00\x04\x08\x08\x08\x08\x03def\x00\x00\x01\x00\x01\x00\x00\x00<\x00\x04\x08\x08\x08\x08"

foo = b"\x08_\x81\x00\x00\x01\x00\x01\x00\x00\x00\x00\x03abc\x11longassdomainname\x03com\x00\x00\x01\x00\x01\x03abc\x11longassdomainname\x03com\x00\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x7f\x00\x00\x01"
print(foo[55:60])
b"\x03abc\x11longassdomainname\x03com\x00\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x7f\x00\x00\x01"
