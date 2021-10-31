

.PHONY: manuf
manuf:
	curl 'https://gitlab.com/wireshark/wireshark/raw/master/manuf' -o pkg/manuf/manuf
	python3 pkg/manuf/make_manuf.py
