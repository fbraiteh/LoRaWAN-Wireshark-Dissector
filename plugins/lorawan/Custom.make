#

_CUSTOM_SUBDIRS_ = \
	lorawan

_CUSTOM_EXTRA_DIST_ = \
	lorawan.m4 \
	lorawan.make

_CUSTOM_plugin_ldadd_ = \
	-dlopen plugins/lorawan/lorawan.la
