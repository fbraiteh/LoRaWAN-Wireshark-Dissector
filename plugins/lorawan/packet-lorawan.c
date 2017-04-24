#include <stdio.h>
#include "config.h"
#include <epan/packet.h>
#include <stdbool.h>


#define LORAWAN_PORT 2404

static gint ett_lorawan = -1;
static gint ett_mhdr = -1;
static gint ett_fctrl = -1;
static gint ett_fopts = -1;

static int proto_lorawan = -1;
static int hf_lorawan_mhdr = -1;
static int hf_mhdr_mtype = -1;
static int hf_mhdr_rfu = -1;
static int hf_mhdr_major= -1 ;
 
static int hf_lorawan_devaddr= -1  ;
static int hf_lorawan_appeui = -1 ;
static int hf_lorawan_deveui= -1 ;
static int hf_lorawan_devnonce = -1 ;
static int hf_lorawan_appnonce = -1 ;
static int hf_lorawan_netid = -1 ;
static int hf_lorawan_dlsettings= -1  ;
static int hf_lorawan_rxdelay= -1  ;
static int hf_lorawan_fctrl= -1  ;
static int hf_lorawan_fcnt= -1  ;

static int hf_fctrl_adr = -1 ;
static int hf_fctrl_rfu6 = -1 ;
static int hf_fctrl_adrackreq = -1 ;
static int hf_fctrl_ack= -1 ;
static int hf_fctrl_fpending= -1  ;
static int hf_fctrl_rfu4 = -1 ;
static int hf_fctrl_foptslen = -1 ;
 

typedef struct {
 gint ett_DrTxP;
 gint ett_chmask ;
 gint ett_dlsettings;
 gint ett_drrange ;
 gint ett_status ;
 gint ett_newchstatus ;

 int hf_lorawan_mic ;
 int hf_lorawan_fopts ;
 int hf_fopts_foption ;
 int hf_dlfopt_CID ;
 int hf_ulfopt_CID ;
 int hf_dlfopt_margin ;
 int hf_dlfopt_gwCnt ;
 int hf_lorawan_fport ;
 int hf_lorawan_frmpayload ;

 int hf_dlfopt_DrTxP ;
 int hf_dlfopt_chmask ;
 int hf_dlfopt_redundancy ;
 int hf_dlfopt_maxdcycle ;
 int hf_dlfopt_dlsettings ;
 int hf_dlfopt_frequency ;
 int hf_dlfopt_chindex ;
 int hf_dlfopt_drrange ;
 int hf_dlfopt_freq ;
 int hf_dlfopt_settings ;
 int hf_ulfopt_rxstatus ;
 int hf_ulfopt_margindevreq ;
 int hf_ulfopt_battery;
 int hf_ulfopt_newchstatus;
 int hf_ulfopt_status ;

 int hf_DrTxP_datarate;
 int hf_DrTxP_txpower;
 int hf_chmask_rfu;
 int hf_chmask_cntl;
 int hf_chmask_nbrep;
 int hf_dlsettings_rfu;
 int hf_dlsettings_RX1droffset;
 int hf_dlsettings_RX2datarate;
 int hf_drrange_Maxdr;
 int hf_drrange_Mindr;
 int hf_status_rfu;
 int hf_status_powerACK;
 int hf_status_datarateACK;
 int hf_status_chmaskACK;
 int hf_newchstatus_rfu ;
 int hf_newchstatus_dataraterangeOK;
 int hf_newchstatus_chfreqOK;

} FOpts_MAC1;

static FOpts_MAC1 FOpts_MAC;

#define MTYPE(a, b, c) ((a << 2) | (b << 1) | (c << 0))

#define JOINREQUEST     MTYPE(0, 0, 0)
#define JOINACCEPT      MTYPE(0, 0, 1)
#define UNCONFUP        MTYPE(0, 1, 0)
#define UNCONFDOWN      MTYPE(0, 1, 1)
#define CONFUP          MTYPE(1, 0, 0)
#define CONFDOWN        MTYPE(1, 0, 1)
#define RFU             MTYPE(1, 1, 0)
#define PROP            MTYPE(1, 1, 1)

static value_string const mhdr_mtype[] = {
    {JOINREQUEST,   "Join Request"},
    {JOINACCEPT,    "Join Accept"},
    {UNCONFUP,      "Unconfirmed Data Up"},
    {UNCONFDOWN,    "Unconfirmed Data Down"},
    {CONFUP,        "Confirmed Data Up"},
    {CONFDOWN,      "Confirmed Data Down"},
    {RFU,           "Reserved for Future Usage"},
    {PROP,          "Proprietary"},
    {0,             NULL}
};
// MAC commands
// a command is unknown if code > MAXKNOWNOPTION
// or length reported by table is 0

// uplink MAC commands
#define LINKCHECKREQ     0x02
#define LINKADRANS       0x03
#define DUTYCYCLEANS     0x04
#define RXPARAMSETUPANS  0x05
#define DEVSTATUSANS     0x06
#define NEWCHANNELANS    0x07
#define RXTIMINGSETUPANS 0x08
#define TXPARAMSETUPANS  0x09
#define DLCHANNELANS     0x0A

// size of MAC commands, including CID byte
// 0 means unknown
static guint8 const ul_command_length[] = {
    0, // 0 unknown
    0, // 1 unknown
    1, // LINKCHECKREQ     0x02
    2, // LINKADRANS       0x03
    1, // DUTYCYCLEANS     0x04
    2, // RXPARAMSETUPANS  0x05
    3, // DEVSTATUSANS     0x06
    2, // NEWCHANNELANS    0x07
    1, // RXTIMINGSETUPANS 0x08
    1, // TXPARAMSETUPANS  0x09
    2  // DLCHANNELANS     0x0A
};

// downlink MAC commands
#define LINKCHECKANS     0x02
#define LINKADRREQ       0x03
#define DUTYCYCLEREQ     0x04
#define RXPARAMSETUPREQ  0x05
#define DEVSTATUSREQ     0x06
#define NEWCHANNELREQ    0x07
#define RXTIMINGSETUPREQ 0x08
#define TXPARAMSETUPREQ  0x09
#define DLCHANNELREQ     0x0A

#define MAXKNOWNOPTION   0x0A

static guint8 const dl_command_length[] = {
    0, // 0 unknown
    0, // 1 unknown
    3, // LINKCHECKANS     0x02
    5, // LINKADRREQ       0x03
    2, // DUTYCYCLEREQ     0x04
    5, // RXPARAMSETUPREQ  0x05
    1, // DEVSTATUSREQ     0x06
    6, // NEWCHANNELREQ    0x07
    2, // RXTIMINGSETUPREQ 0x08
    2, // TXPARAMSETUPREQ  0x09
    5  // DLCHANNELREQ     0x0A
};

static value_string const dl_fopts_optiontype[] = {
    {LINKCHECKANS,      "LinkCheckAns"    },
    {LINKADRREQ,        "LinkADRReq"      },
    {DUTYCYCLEREQ,      "DutyCycleReq"    },
    {RXPARAMSETUPREQ,   "RxParamSetupReq" },
    {DEVSTATUSREQ,      "DevStatusReq"    },
    {NEWCHANNELREQ,     "NewChannelReq"   },
    {RXTIMINGSETUPREQ,  "RxTimingSetupReq"},
    {TXPARAMSETUPREQ,   "TxParamSetupReq" },
    {DLCHANNELREQ,      "DlChannelReq"    },
    {0,                 NULL}
};

static value_string const ul_fopts_optiontype[] = {
    {LINKCHECKREQ,      "LinkCheckReq"    },
    {LINKADRANS,        "LinkADRAns"      },
    {DUTYCYCLEANS,      "DutyCycleAns"    },
    {RXPARAMSETUPANS,   "RxParamSetupAns" },
    {DEVSTATUSANS,      "DevStatusAns"    },
    {NEWCHANNELANS,     "NewChannelAns"   },
    {RXTIMINGSETUPANS,  "RxTimingSetupAns"},
    {TXPARAMSETUPANS,   "TxParamSetupAns" },
    {DLCHANNELANS,      "DlChannelAns"    },
    {0,                 NULL}
};

  
static void
dissect_Option_DrTxP(tvbuff_t *tvb, int offset, proto_tree *tree);
static void
dissect_Option_chmask(tvbuff_t *tvb, int offset, proto_tree *tree);
static void
dissect_Option_dlsettings(tvbuff_t *tvb, int offset, proto_tree *tree);
static void
dissect_Option_drrange(tvbuff_t *tvb, int offset, proto_tree *tree);
static void
dissect_Option_status(tvbuff_t *tvb, int offset, proto_tree *tree);
static void
dissect_Option_newchstatus(tvbuff_t *tvb, int offset, proto_tree *tree);

static void 
dissect_Options(tvbuff_t *tvb, int offset, proto_tree *lorawan_tree, bool downlink_frame); 



/* The main function */
static int
dissect_lorawan(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{

	guint offset = 0;
        void * temp; // this avoids a compile warning
        temp = data; // same
        data = temp; // same

        col_set_str(pinfo->cinfo, COL_PROTOCOL, "LoRaWAN");
        col_clear(pinfo->cinfo, COL_INFO);


        proto_item *ti = proto_tree_add_item(tree, proto_lorawan, tvb, 0, -1, ENC_NA);
        proto_tree *lorawan_tree = proto_item_add_subtree(ti, ett_lorawan);
        

        // process Mac Header (MHDR)
        guint8 mhdr = tvb_get_bits8(tvb, 0, 3);
        proto_item *mhdr_ti;
        proto_tree *mhdr_tree;
        mhdr_ti = proto_tree_add_item(lorawan_tree, hf_lorawan_mhdr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        mhdr_tree = proto_item_add_subtree(mhdr_ti, ett_mhdr);
        proto_tree_add_item(mhdr_tree, hf_mhdr_mtype, tvb, offset, 1, mhdr);
        proto_tree_add_item(mhdr_tree, hf_mhdr_rfu, tvb, offset, 1, mhdr);
        proto_tree_add_item(mhdr_tree, hf_mhdr_major, tvb, offset, 1, mhdr);
        offset += 1;

        bool downlink_frame; // DL if true, UL if false
        if((mhdr & 1) == 1)  // odd-numbered Mtype frames happen to be all downlink, even-numbered uplink
        {                    // beware of RFU and proprietary, though!
            downlink_frame = true;
        }
        else
        {
            downlink_frame = false;
        }       

        switch (mhdr) {
        // Join messages
        case JOINREQUEST : 
            proto_tree_add_item(lorawan_tree, hf_lorawan_appeui, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_item(lorawan_tree, hf_lorawan_deveui, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_item(lorawan_tree, hf_lorawan_devnonce, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            break;
        case JOINACCEPT : 
            proto_tree_add_item(lorawan_tree, hf_lorawan_appnonce, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            offset += 3;
            proto_tree_add_item(lorawan_tree, hf_lorawan_netid, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            offset += 3;
            proto_tree_add_item(lorawan_tree, hf_lorawan_devaddr, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(lorawan_tree, hf_lorawan_dlsettings, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item(lorawan_tree, hf_lorawan_rxdelay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            break;
        // Data messages
        case UNCONFUP : 
        case UNCONFDOWN : 
        case CONFUP : 
        case CONFDOWN : 
            // process Frame Header (FHDR)
            proto_tree_add_item(lorawan_tree, hf_lorawan_devaddr, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_item *fctrl_ti;
            fctrl_ti = proto_tree_add_item(lorawan_tree, hf_lorawan_fctrl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree *fctrl_tree;
            fctrl_tree = proto_item_add_subtree(fctrl_ti, ett_fctrl);
            if(downlink_frame == true)
            {
                proto_tree_add_item(fctrl_tree, hf_fctrl_adr, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(fctrl_tree, hf_fctrl_rfu6, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(fctrl_tree, hf_fctrl_ack, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(fctrl_tree, hf_fctrl_fpending, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(fctrl_tree, hf_fctrl_foptslen, tvb, offset, 1, ENC_NA);    
            }
            else
            {
                proto_tree_add_item(fctrl_tree, hf_fctrl_adr, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(fctrl_tree, hf_fctrl_adrackreq, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(fctrl_tree, hf_fctrl_ack, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(fctrl_tree, hf_fctrl_rfu4, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(fctrl_tree, hf_fctrl_foptslen, tvb, offset, 1, ENC_NA);
            }
           
           dissect_Options(tvb, offset, lorawan_tree, downlink_frame);
           
            break; 
       case PROP : 
            break;
       case RFU : 
            break;
       default:
            // all possible cases are covered, one should never reach default
            break;
      }
 	       proto_tree_add_item(lorawan_tree, FOpts_MAC.hf_lorawan_mic, tvb, offset, 4, ENC_NA);
         return tvb_captured_length(tvb);

}

void
proto_register_lorawan(void)
{

     memset(&FOpts_MAC, -1, sizeof(FOpts_MAC1) );

    static hf_register_info hf[] = {
        { &hf_lorawan_mhdr, { "MHDR", "lorawan.mhdr", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lorawan_appeui, { "AppEUI", "lorawan.appeui", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lorawan_deveui, { "DevEUI", "lorawan.deveui", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lorawan_devaddr, { "DevAddr", "lorawan.devaddr", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lorawan_dlsettings, { "DLSettings", "lorawan.dlsettings", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lorawan_devnonce, { "DevNonce", "lorawan.devnonce", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lorawan_appnonce, { "AppNonce", "lorawan.appnonce", FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lorawan_netid, { "NetID", "lorawan.netid", FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lorawan_rxdelay, { "RxDelay", "lorawan.rxdelay", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lorawan_fctrl, { "FCtrl", "lorawan.fctrl", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lorawan_fcnt, { "FCnt", "lorawan.fcnt", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_mhdr_mtype, { "MType", "lorawan.mhdr.mtype", FT_UINT8, BASE_HEX, VALS(&mhdr_mtype), (1 << 7) | (1 << 6) | (1 << 5), NULL, HFILL }},
        { &hf_mhdr_rfu, { "Reserved", "lorawan.mhdr.rfu", FT_BOOLEAN, 8, TFS(&tfs_set_notset), (1 << 4) | (1 << 3) | (1 << 2), NULL, HFILL }},
        { &hf_mhdr_major, { "Major", "lorawan.mhdr.major", FT_UINT8, BASE_DEC, NULL, (1 << 1) | (1 << 0), NULL, HFILL }},
        
	    { &hf_fctrl_adr, { "ADR (Adaptative Data Rate)", "lorawan.fctrl.adr", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), (1 << 7), NULL, HFILL }},
        { &hf_fctrl_adrackreq, { "ADRACKReq", "lorawan.fctrl.adrackreq", FT_BOOLEAN, 8, TFS(&tfs_set_notset), (1 << 6), NULL, HFILL }},
        { &hf_fctrl_rfu6, { "RFU", "lorawan.fctrl.rfu6", FT_BOOLEAN, 8, TFS(&tfs_set_notset), (1 << 6), NULL, HFILL }},
        { &hf_fctrl_ack, { "ACK", "lorawan.fctrl.ack", FT_BOOLEAN, 8, TFS(&tfs_ack_nack), (1 << 5), NULL, HFILL }},
        { &hf_fctrl_rfu4, { "RFU", "lorawan.fctrl.rfu4", FT_BOOLEAN, 8, TFS(&tfs_set_notset), (1 << 4), NULL, HFILL }},
        { &hf_fctrl_fpending, { "FPending", "lorawan.fctrl.fpending", FT_BOOLEAN, 8, TFS(&tfs_set_notset), (1 << 4), NULL, HFILL }},
        { &hf_fctrl_foptslen, { "FOptsLen", "lorawan.fctrl.foptslen", FT_UINT8, BASE_DEC, NULL, (1 << 3) | (1 << 2) | (1 << 1) | (1 << 0), NULL, HFILL, }},
        { &FOpts_MAC.hf_lorawan_fopts, { "FOpts", "lorawan.fopts", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &FOpts_MAC.hf_fopts_foption, { "FOption", "lorawan.fopts.foption", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &FOpts_MAC.hf_dlfopt_CID, { "dlCID", "lorawan.fopts.foption.dlCID", FT_UINT8, BASE_HEX, VALS(&dl_fopts_optiontype), 0x00, NULL, HFILL }},
        { &FOpts_MAC.hf_ulfopt_CID, { "ulCID", "lorawan.fopts.foption.ulCID", FT_UINT8, BASE_HEX, VALS(&ul_fopts_optiontype), 0x00, NULL, HFILL }},
        { &FOpts_MAC.hf_dlfopt_margin, { "Margin", "lorawan.fopts.foption.margin", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &FOpts_MAC.hf_dlfopt_gwCnt, { "Gateway Count", "lorawan.fopts.foption.gwcnt", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &FOpts_MAC.hf_lorawan_fport, { "FPort", "lorawan.fport", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &FOpts_MAC.hf_lorawan_frmpayload, { "FRMPayload", "lorawan.frmpayload", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &FOpts_MAC.hf_lorawan_mic, { "MIC", "lorawan.mic", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    	
    	{ &FOpts_MAC.hf_dlfopt_DrTxP, { "DataRate_TxPower", "lorawan.fopts.foption.DrTxP", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
    	{ &FOpts_MAC.hf_dlfopt_chmask, { "ChMask", "lorawan.fopts.foption.chmask", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
    	{ &FOpts_MAC.hf_dlfopt_redundancy, { "Redundancy", "lorawan.fopts.foption.redundancy", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
    	{ &FOpts_MAC.hf_dlfopt_maxdcycle, { "MaxDCycle", "lorawan.fopts.foption.maxdcycle", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
    	{ &FOpts_MAC.hf_dlfopt_dlsettings, { "DLsettings", "lorawan.fopts.foption.dlsettings", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
    	{ &FOpts_MAC.hf_dlfopt_frequency, { "Frequency", "lorawan.fopts.foption.frequency", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
    	{ &FOpts_MAC.hf_dlfopt_chindex, { "ChIndex", "lorawan.fopts.foption.chindex", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
    	{ &FOpts_MAC.hf_dlfopt_freq, { "Freq", "lorawan.fopts.foption.freq", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
    	{ &FOpts_MAC.hf_dlfopt_drrange, { "DrRange", "lorawan.fopts.foption.drrange", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
    	{ &FOpts_MAC.hf_dlfopt_settings, { "Settings", "lorawan.fopts.foption.settings", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &FOpts_MAC.hf_ulfopt_status, { "Status", "lorawan.fopts.foption.status", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
    	{ &FOpts_MAC.hf_ulfopt_rxstatus, { "RxStatus", "lorawan.fopts.foption.rxstatus", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
    	{ &FOpts_MAC.hf_ulfopt_margindevreq, { "MarginDevReq", "lorawan.fopts.foption.margindevreq", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
    	{ &FOpts_MAC.hf_ulfopt_battery, { "Battery", "lorawan.fopts.foption.battery", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
    	{ &FOpts_MAC.hf_ulfopt_newchstatus, { "NewChannelStatus", "lorawan.fopts.foption.newchstatus", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},

    	{ &FOpts_MAC.hf_DrTxP_datarate, { "DataRate", "lorawan.fopts.foption.DrTxP.datarate", FT_UINT8, BASE_DEC, NULL,  (1 << 7) | (1 << 6) | (1 << 5) | (1 << 4), NULL, HFILL }},
    	{ &FOpts_MAC.hf_DrTxP_txpower, { "TxPower", "lorawan.fopts.foption.DrTxP.txpower",  FT_UINT8, BASE_DEC, NULL,  (1 << 3) | (1 << 2) | (1 << 1) | (1 << 0), NULL, HFILL }},
    	{ &FOpts_MAC.hf_chmask_rfu, { "ChMaskRFU", "lorawan.fopts.foption.chmask.rfu", FT_UINT8, BASE_DEC, NULL,  (1 << 7), NULL, HFILL }},
    	{ &FOpts_MAC.hf_chmask_cntl, { "ChMaskCntrl", "lorawan.fopts.foption.chmask.cntrl", FT_UINT8, BASE_DEC, NULL,   (1 << 6) | (1 << 5) | (1 << 4), NULL, HFILL }},
    	{ &FOpts_MAC.hf_chmask_nbrep, { "ChmaskNbRep", "lorawan.fopts.foption.chmask.nbrep", FT_UINT8, BASE_DEC, NULL,  (1 << 3) | (1 << 2) | (1 << 1) | (1 << 0), NULL, HFILL }},
    	{ &FOpts_MAC.hf_dlsettings_rfu, { "DlSettingsRFU", "lorawan.fopts.foption.dlsettings.rfu", FT_UINT8, BASE_DEC, NULL,  (1 << 7), NULL, HFILL }},
    	{ &FOpts_MAC.hf_dlsettings_RX1droffset, { "RX1DataRateOffset", "lorawan.fopts.foption.dlsettings.RX1droffset", FT_UINT8, BASE_DEC, NULL,   (1 << 6) | (1 << 5) | (1 << 4), NULL, HFILL }},
    	{ &FOpts_MAC.hf_dlsettings_RX2datarate, { "RX2DataRate", "lorawan.fopts.foption.dlsettings.RX2datarate", FT_UINT8, BASE_DEC, NULL,  (1 << 3) | (1 << 2) | (1 << 1) | (1 << 0), NULL, HFILL }},
    	{ &FOpts_MAC.hf_drrange_Maxdr, { "MaxDataRate", "lorawan.fopts.foption.drrange.Maxdr", FT_UINT8, BASE_DEC, NULL,  (1 << 7) | (1 << 6) | (1 << 5) | (1 << 4), NULL, HFILL }},
    	{ &FOpts_MAC.hf_drrange_Mindr, { "MinDataRate", "lorawan.fopts.foption.drrange.Mindr", FT_UINT8, BASE_DEC, NULL,  (1 << 3) | (1 << 2) | (1 << 1) | (1 << 0), NULL, HFILL }},
    	{ &FOpts_MAC.hf_status_rfu, { "StatusRFU", "lorawan.fopts.foption.status.rfu", FT_UINT8, BASE_DEC, NULL,   (1 << 7) | (1 << 6) | (1 << 5) | (1 << 4)| (1 << 3), NULL, HFILL }},
    	{ &FOpts_MAC.hf_status_powerACK, { "PowerACK", "lorawan.fopts.foption.status.powerACK", FT_UINT8, BASE_DEC, NULL,  (1 << 2), NULL, HFILL }},
    	{ &FOpts_MAC.hf_status_datarateACK, { "DataRateACK", "lorawan.fopts.foption.status.datarateACK", FT_UINT8, BASE_DEC, NULL,  (1 << 1), NULL, HFILL }},
    	{ &FOpts_MAC.hf_status_chmaskACK, { "ChannelMaskACK", "lorawan.fopts.foption.status.chmaskACK", FT_UINT8, BASE_DEC, NULL,  (1 << 0), NULL, HFILL }},
    	{ &FOpts_MAC.hf_newchstatus_rfu, { "NewChannelStatusRFU", "lorawan.fopts.foption.newchstatus.rfu", FT_UINT8, BASE_DEC, NULL,   (1 << 7) | (1 << 6) | (1 << 5) | (1 << 4)| (1 << 3)| (1 << 2), NULL, HFILL }},
    	{ &FOpts_MAC.hf_newchstatus_dataraterangeOK, { "NewChannelStatusDataRangeOK", "lorawan.fopts.foption.newchstatus.dataraterangeOK",  FT_UINT8, BASE_DEC, NULL, (1 << 1), NULL, HFILL }},
      	{ &FOpts_MAC.hf_newchstatus_chfreqOK, { "NewChannelStatusChannelFreqOK", "lorawan.fopts.foption.newchstatus.chfreqOK",  FT_UINT8, BASE_DEC, NULL, (1 << 0), NULL, HFILL }},

};

static gint *ett[] = {
        
        &ett_lorawan,
        &ett_mhdr,
        &ett_fctrl,
        &ett_fopts,
    	&FOpts_MAC.ett_DrTxP,
    	&FOpts_MAC.ett_chmask,
    	&FOpts_MAC.ett_dlsettings,
    	&FOpts_MAC.ett_drrange,
    	&FOpts_MAC.ett_status,
    	&FOpts_MAC.ett_newchstatus

    };

    proto_lorawan = proto_register_protocol(
        "LoRaWAN 1.0.2",
        "lorawan",
        "lorawan"
    );

    proto_register_field_array(proto_lorawan, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    
    /*  Register dissectors with Wireshark. */
    register_dissector("lorawan", (dissector_t) dissect_lorawan, proto_lorawan);
    }
 
 /***** Options Subtree Functions *****/    
static void
dissect_Option_DrTxP(tvbuff_t *tvb, int offset, proto_tree *tree)
{
  proto_tree *type_tree;
  proto_item *ti;

  ti = proto_tree_add_item(tree, FOpts_MAC.hf_dlfopt_DrTxP, tvb, offset+1, 1, ENC_NA);
  type_tree = proto_item_add_subtree(ti, FOpts_MAC.ett_DrTxP);
  proto_tree_add_item(type_tree, FOpts_MAC.hf_DrTxP_datarate, tvb, offset+1, 1, ENC_NA); 
  proto_tree_add_item(type_tree, FOpts_MAC.hf_DrTxP_txpower, tvb, offset+1, 1, ENC_NA);
  
} 
 
 static void
dissect_Option_chmask(tvbuff_t *tvb, int offset, proto_tree *tree)
{
  proto_tree *type_tree;
  proto_item *ti;

  ti = proto_tree_add_item(tree, FOpts_MAC.hf_dlfopt_chmask, tvb, offset+2, 1, ENC_NA);
  type_tree = proto_item_add_subtree(ti, FOpts_MAC.ett_chmask);
                       
  proto_tree_add_item(type_tree, FOpts_MAC.hf_chmask_rfu, tvb, offset+2, 1, ENC_NA); 
  proto_tree_add_item(type_tree, FOpts_MAC.hf_chmask_cntl, tvb, offset+2, 1, ENC_NA);
  proto_tree_add_item(type_tree, FOpts_MAC.hf_chmask_nbrep, tvb, offset+2, 1, ENC_NA);            
  
}
 
 static void
dissect_Option_dlsettings(tvbuff_t *tvb, int offset, proto_tree *tree)
{
  proto_tree *type_tree;
  proto_item *ti;

  ti = proto_tree_add_item(tree, FOpts_MAC.hf_dlfopt_dlsettings, tvb, offset+1, 1, ENC_NA);
  type_tree = proto_item_add_subtree(ti, FOpts_MAC.ett_dlsettings);
  proto_tree_add_item(type_tree, FOpts_MAC.hf_dlsettings_rfu, tvb, offset+1, 1, ENC_NA); 
  proto_tree_add_item(type_tree, FOpts_MAC.hf_dlsettings_RX1droffset, tvb, offset+1, 1, ENC_NA);
  proto_tree_add_item(type_tree, FOpts_MAC.hf_dlsettings_RX2datarate, tvb, offset+1, 1, ENC_NA);
                                
}
    
 static void
dissect_Option_drrange(tvbuff_t *tvb, int offset, proto_tree *tree)
{
  proto_tree *type_tree;
  proto_item *ti;

  ti = proto_tree_add_item(tree, FOpts_MAC.hf_dlfopt_drrange, tvb, offset+3, 1, ENC_NA);
  type_tree = proto_item_add_subtree(ti, FOpts_MAC.ett_drrange);
  proto_tree_add_item(type_tree, FOpts_MAC.hf_drrange_Maxdr, tvb, offset+3, 1, ENC_NA); 
  proto_tree_add_item(type_tree, FOpts_MAC.hf_drrange_Mindr, tvb, offset+3, 1, ENC_NA);

}   
    
static void
dissect_Option_status(tvbuff_t *tvb, int offset, proto_tree *tree)
{
  proto_tree *type_tree;
  proto_item *ti;

  ti = proto_tree_add_item(tree, FOpts_MAC.hf_ulfopt_status, tvb, offset+1, 1, ENC_NA);
  type_tree = proto_item_add_subtree(ti, FOpts_MAC.ett_status);
  proto_tree_add_item(type_tree, FOpts_MAC.hf_status_rfu, tvb, offset+1, 1, ENC_NA); 
  proto_tree_add_item(type_tree, FOpts_MAC.hf_status_powerACK, tvb, offset+1, 1, ENC_NA);
  proto_tree_add_item(type_tree, FOpts_MAC.hf_status_datarateACK, tvb, offset+1, 1, ENC_NA);
  proto_tree_add_item(type_tree, FOpts_MAC.hf_status_chmaskACK, tvb, offset+1, 1, ENC_NA);
}
    
static void
dissect_Option_newchstatus(tvbuff_t *tvb, int offset, proto_tree *tree)
{
  proto_tree *type_tree;
  proto_item *ti;

  ti = proto_tree_add_item(tree, FOpts_MAC.hf_ulfopt_newchstatus, tvb, offset+1, 1, ENC_NA);
  type_tree = proto_item_add_subtree(ti, FOpts_MAC.ett_newchstatus);
  proto_tree_add_item(type_tree, FOpts_MAC.hf_newchstatus_rfu, tvb, offset+1, 1, ENC_NA); 
  proto_tree_add_item(type_tree, FOpts_MAC.hf_newchstatus_dataraterangeOK, tvb, offset+1, 1, ENC_NA);
  proto_tree_add_item(type_tree, FOpts_MAC.hf_newchstatus_chfreqOK, tvb, offset+1, 1, ENC_NA);

}    

/***** Dissect Options *****/ 

static void 
dissect_Options(tvbuff_t *tvb, int offset, proto_tree *lorawan_tree, bool downlink_frame){
 guint8 foptslen;
            foptslen = tvb_get_bits8(tvb, offset*8 + 4, 4);
            offset += 1;
            proto_tree_add_item(lorawan_tree, hf_lorawan_fcnt, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            // process 0 to 15 bytes of Frame Options (FOpts)
            if (foptslen > 0)  // FPort!=0 if present
            {
                printf ("foptslen = %d\n", foptslen);
                guint offset_to_options = offset; // remember index to beginning of options, in case we need to skip over unknown options
                proto_item *opts_item;
                opts_item = proto_tree_add_item(lorawan_tree, FOpts_MAC.hf_lorawan_fopts, tvb, offset, foptslen, ENC_NA);
                proto_tree *opts_tree;
                opts_tree = proto_item_add_subtree(opts_item, ett_fopts);
                guint8 remaining_optslen;
                remaining_optslen=foptslen;
                while (remaining_optslen>0) {
                    guint8 foption;
                    foption = tvb_get_guint8(tvb, offset);
                    // test for unknown option (either greater than MAXKNOWNOPTION or length in table is 0)
                    if (foption > MAXKNOWNOPTION) {
                        printf ("unknown MAC command code in FOptions : %d\n", foption);
                        break;
                    }
                    guint8 foption_length;
                    foption_length = (downlink_frame ? dl_command_length[foption] : ul_command_length[foption]);
                    if (foption_length == 0) {
                        printf ("unknown MAC command code in FOptions : %d\n", foption);
                        break;
                    }
                    if (foption_length<=remaining_optslen) { // double check that this option does not extend past the option bytes
                        proto_item *fopt_ti;
                        fopt_ti = proto_tree_add_item(opts_tree, FOpts_MAC.hf_fopts_foption, tvb, offset, foption_length, ENC_NA);
                        proto_tree *fopt_tree;
                        fopt_tree = proto_item_add_subtree(fopt_ti, ett_fopts);
                        if (downlink_frame) 
                        {
                            proto_tree_add_item(fopt_tree, FOpts_MAC.hf_dlfopt_CID, tvb, offset, 1, ENC_NA);
			  
			  switch (foption) 
                            {
                            case LINKCHECKANS:
			                   // 2 bytes Margin and GwCnt
                                proto_tree_add_item(fopt_tree, FOpts_MAC.hf_dlfopt_margin, tvb, offset+1, 1, ENC_NA);
                                proto_tree_add_item(fopt_tree, FOpts_MAC.hf_dlfopt_gwCnt, tvb, offset+2, 1, ENC_NA);
                			 break; 
                            case LINKADRREQ:
                                          // 4 bytes: DataRate_TXPower: DrTxP(1), ChMask(2), Redundancy (1)
                                proto_tree_add_item(fopt_tree, FOpts_MAC.hf_dlfopt_DrTxP, tvb, offset+1, 1, ENC_NA);                        
                             	dissect_Option_DrTxP(tvb, offset, fopt_tree);


                                proto_tree_add_item(fopt_tree, FOpts_MAC.hf_dlfopt_chmask, tvb, offset+2, 2, ENC_LITTLE_ENDIAN);
				dissect_Option_chmask(tvb, offset, fopt_tree);

                     		proto_tree_add_item(fopt_tree, FOpts_MAC.hf_dlfopt_redundancy, tvb, offset+3, 1, ENC_NA);

                			break;

                            case DUTYCYCLEREQ: 
                 			// 1 byte: MaxDCycle
                		proto_tree_add_item(fopt_tree, FOpts_MAC.hf_dlfopt_maxdcycle, tvb, offset+1, 1, ENC_NA);
				       break;

                            case RXPARAMSETUPREQ:
                			//4 bytes: DLsettings(1) and Frequency (3)
                		proto_tree_add_item(fopt_tree, FOpts_MAC.hf_dlfopt_dlsettings, tvb, offset+1, 1, ENC_NA);
                                dissect_Option_dlsettings(tvb, offset, fopt_tree);		
                                
				proto_tree_add_item(fopt_tree, FOpts_MAC.hf_dlfopt_frequency, tvb, offset+2, 3, ENC_LITTLE_ENDIAN);
					 
					 break;

                            case DEVSTATUSREQ:
        					      
        				 break;

                            case NEWCHANNELREQ:
					 // 5 bytes: ChIndex (1), Freq(3), DrRange (1)
                                proto_tree_add_item(fopt_tree, FOpts_MAC.hf_dlfopt_chindex, tvb, offset+1, 1, ENC_NA);
                                proto_tree_add_item(fopt_tree, FOpts_MAC.hf_dlfopt_freq, tvb, offset+2, 3, ENC_LITTLE_ENDIAN);
                                
                                proto_tree_add_item(fopt_tree, FOpts_MAC.hf_dlfopt_drrange, tvb, offset+3, 1, ENC_NA);
				dissect_Option_drrange(tvb, offset, fopt_tree);
                               
                            		break;

                            case RXTIMINGSETUPREQ:
                			//one byte: Settings
                		proto_tree_add_item(fopt_tree, FOpts_MAC.hf_dlfopt_settings, tvb, offset+1, 1, ENC_NA);
                			break;

                            case TXPARAMSETUPREQ:
					break;
                            case DLCHANNELREQ:

                                	break;

                            default:
                                	break;
                            }
                        }
                        else {
                                proto_tree_add_item(fopt_tree, FOpts_MAC.hf_ulfopt_CID, tvb, offset, 1, ENC_NA);
                                switch (foption){

                                    case LINKCHECKREQ: 
                					
                				 break;
                                    case LINKADRANS:
                        			//one byte: Status
                        		proto_tree_add_item(fopt_tree, FOpts_MAC.hf_ulfopt_status, tvb, offset+1, 1, ENC_NA);
					dissect_Option_status(tvb, offset, fopt_tree);
                                        

                        			  break;
                                    case DUTYCYCLEANS:
        					  break;
                                    case RXPARAMSETUPANS:
                        			//one byte
                        		proto_tree_add_item(fopt_tree, FOpts_MAC.hf_ulfopt_rxstatus, tvb, offset+1, 1, ENC_NA);

        					  break;
                                    case DEVSTATUSANS:
        					// 2 bytes: Battery, Margin (for the last received DevStatusReq)
                                        proto_tree_add_item(fopt_tree, FOpts_MAC.hf_ulfopt_margindevreq, tvb, offset+2, 1, ENC_NA);
                                        proto_tree_add_item(fopt_tree, FOpts_MAC.hf_ulfopt_battery, tvb, offset+1, 1, ENC_NA);
                        			   break;
                                    case NEWCHANNELANS:
                    				//one byte
                    			proto_tree_add_item(fopt_tree, FOpts_MAC.hf_ulfopt_newchstatus, tvb, offset+1, 1, ENC_NA);
                                        dissect_Option_newchstatus(tvb, offset, fopt_tree);

						   break;
                                    case RXTIMINGSETUPANS:
        					        
                                    case TXPARAMSETUPANS:
                                        	   break;
                                    default:
                                       		  break;
                            }
                        }
                        offset += foption_length;
                        remaining_optslen -= foption_length;
                    }
                    else { // we have a problem, stop dissecting options and report
                        printf ("%d extraneous bytes while processing frame options\n", remaining_optslen);
                        break;
                    }

                }
                offset = offset_to_options + foptslen; // set offset fresh from start of option bytes
            }
            
            // if payload not empty, 1 byte of FPort and variable number of bytes of actual payload
            guint payload_length;
            if (tvb_reported_length(tvb) == tvb_captured_length(tvb)) {
                payload_length = tvb_captured_length(tvb)-offset-4;
                printf ("payload length : %d\n", payload_length);
                // do the job
                if (payload_length>0){ 
                    if (foptslen !=0 && FOpts_MAC.hf_lorawan_fport == 0){
                    
                    printf("Error: %s\n", "FPort zero can not be used");
                    
                    } else{
                    proto_tree_add_item(lorawan_tree, FOpts_MAC.hf_lorawan_fport, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    }
                }
                if (payload_length>1) {
                    proto_tree_add_item(lorawan_tree, FOpts_MAC.hf_lorawan_frmpayload, tvb, offset, payload_length-1, ENC_NA);
                    offset += payload_length-1;
                    
                    
                //
               
                guint offset_to_options = offset; // remember index to beginning of options, in case we need to skip over unknown options
                proto_item *opts_item;
                opts_item = proto_tree_add_item(lorawan_tree, FOpts_MAC.hf_lorawan_fopts, tvb, offset, payload_length, ENC_NA);
                proto_tree *opts_tree;
                opts_tree = proto_item_add_subtree(opts_item, ett_fopts);
                guint8 remaining_optslen;
                remaining_optslen=payload_length;
                while (remaining_optslen>0) {
                    guint8 foption;
                    foption = tvb_get_guint8(tvb, offset);
                    // test for unknown option (either greater than MAXKNOWNOPTION or length in table is 0)
                    if (foption > MAXKNOWNOPTION) {
                        printf ("unknown MAC command code in FOptions : %d\n", foption);
                        break;
                    }
                    guint8 foption_length;
                    foption_length = (downlink_frame ? dl_command_length[foption] : ul_command_length[foption]);
                    if (foption_length == 0) {
                        printf ("unknown MAC command code in FOptions : %d\n", foption);
                        break;
                    }
                    if (foption_length<=remaining_optslen) { // double check that this option does not extend past the option bytes
                        proto_item *fopt_ti;
                        fopt_ti = proto_tree_add_item(opts_tree, FOpts_MAC.hf_fopts_foption, tvb, offset, foption_length, ENC_NA);
                        proto_tree *fopt_tree;
                        fopt_tree = proto_item_add_subtree(fopt_ti, ett_fopts);
                 if (downlink_frame) 
                        {
                            proto_tree_add_item(fopt_tree, FOpts_MAC.hf_dlfopt_CID, tvb, offset, 1, ENC_NA);
			  
			  switch (foption) 
                            {
                            case LINKCHECKANS:
			                   // 2 bytes Margin and GwCnt
                                proto_tree_add_item(fopt_tree, FOpts_MAC.hf_dlfopt_margin, tvb, offset+1, 1, ENC_NA);
                                proto_tree_add_item(fopt_tree, FOpts_MAC.hf_dlfopt_gwCnt, tvb, offset+2, 1, ENC_NA);
                			 break; 
                            case LINKADRREQ:
                                          // 4 bytes: DataRate_TXPower: DrTxP(1), ChMask(2), Redundancy (1)
                                proto_tree_add_item(fopt_tree, FOpts_MAC.hf_dlfopt_DrTxP, tvb, offset+1, 1, ENC_NA);                        
                             	dissect_Option_DrTxP(tvb, offset, fopt_tree);


                                proto_tree_add_item(fopt_tree, FOpts_MAC.hf_dlfopt_chmask, tvb, offset+2, 2, ENC_LITTLE_ENDIAN);
				dissect_Option_chmask(tvb, offset, fopt_tree);

                     		proto_tree_add_item(fopt_tree, FOpts_MAC.hf_dlfopt_redundancy, tvb, offset+3, 1, ENC_NA);

                			break;

                            case DUTYCYCLEREQ: 
                 			// 1 byte: MaxDCycle
                		proto_tree_add_item(fopt_tree, FOpts_MAC.hf_dlfopt_maxdcycle, tvb, offset+1, 1, ENC_NA);
				       break;

                            case RXPARAMSETUPREQ:
                			//4 bytes: DLsettings(1) and Frequency (3)
                		proto_tree_add_item(fopt_tree, FOpts_MAC.hf_dlfopt_dlsettings, tvb, offset+1, 1, ENC_NA);
                                dissect_Option_dlsettings(tvb, offset, fopt_tree);		
                                
				proto_tree_add_item(fopt_tree, FOpts_MAC.hf_dlfopt_frequency, tvb, offset+2, 3, ENC_LITTLE_ENDIAN);
					 
					 break;

                            case DEVSTATUSREQ:
        					      
        				 break;

                            case NEWCHANNELREQ:
					 // 5 bytes: ChIndex (1), Freq(3), DrRange (1)
                                proto_tree_add_item(fopt_tree, FOpts_MAC.hf_dlfopt_chindex, tvb, offset+1, 1, ENC_NA);
                                proto_tree_add_item(fopt_tree, FOpts_MAC.hf_dlfopt_freq, tvb, offset+2, 3, ENC_LITTLE_ENDIAN);
                                
                                proto_tree_add_item(fopt_tree, FOpts_MAC.hf_dlfopt_drrange, tvb, offset+3, 1, ENC_NA);
				dissect_Option_drrange(tvb, offset, fopt_tree);
                               
                            		break;

                            case RXTIMINGSETUPREQ:
                			//one byte: Settings
                		proto_tree_add_item(fopt_tree, FOpts_MAC.hf_dlfopt_settings, tvb, offset+1, 1, ENC_NA);
                			break;

                            case TXPARAMSETUPREQ:
					break;
                            case DLCHANNELREQ:

                                	break;

                            default:
                                	break;
                            }
                        }
                        else {
                                proto_tree_add_item(fopt_tree, FOpts_MAC.hf_ulfopt_CID, tvb, offset, 1, ENC_NA);
                                switch (foption){

                                    case LINKCHECKREQ: 
                					
                				break;
                                    case LINKADRANS:
                        			//one byte: Status
                        		proto_tree_add_item(fopt_tree, FOpts_MAC.hf_ulfopt_status, tvb, offset+1, 1, ENC_NA);
					dissect_Option_status(tvb, offset, fopt_tree);
                                        

                        			 break;
                                    case DUTYCYCLEANS:
        					 break;
                                    case RXPARAMSETUPANS:
                        			//one byte
                        		proto_tree_add_item(fopt_tree, FOpts_MAC.hf_ulfopt_rxstatus, tvb, offset+1, 1, ENC_NA);

        					  break;
                                    case DEVSTATUSANS:
        					// 2 bytes: Battery, Margin (for the last received DevStatusReq)
                                        proto_tree_add_item(fopt_tree, FOpts_MAC.hf_ulfopt_margindevreq, tvb, offset+2, 1, ENC_NA);
                                        proto_tree_add_item(fopt_tree, FOpts_MAC.hf_ulfopt_battery, tvb, offset+1, 1, ENC_NA);
                        			   break;
                                    case NEWCHANNELANS:
                    				//one byte
                    			proto_tree_add_item(fopt_tree, FOpts_MAC.hf_ulfopt_newchstatus, tvb, offset+1, 1, ENC_NA);
                                        dissect_Option_newchstatus(tvb, offset, fopt_tree);

						   break;
                                    case RXTIMINGSETUPANS:
        					        
                                    case TXPARAMSETUPANS:
                                        	  break;
                                    default:
                                       		 break;
                            }
                        }
                        offset += foption_length;
                        remaining_optslen -= foption_length;
                    }
                    else { // we have a problem, stop dissecting options and report
                        printf ("%d extraneous bytes while processing frame options\n", remaining_optslen);
                        break;
                    }

                }
                offset = offset_to_options + payload_length; // set offset fresh from start of option bytes
            }
                
              
                }
             else {
                // the case were Wireshark did not capture the full packet is not covered, bail out
                exit(1);
            }
            
} 

void
proto_reg_handoff_lorawan(void)
{
//    static dissector_handle_t lorawan_handle;

//    lorawan_handle = create_dissector_handle(dissect_lorawan, proto_lorawan);
//    dissector_add_uint("sensorlab.eventID", 0x34, lorawan_handle);
//    dissector_add_uint("104asdu.addr", 1, lorawan_handle);
//    dissector_add_uint("104asdu.addr", 10, lorawan_handle);
}
