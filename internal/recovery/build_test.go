package recovery

import (
	"encoding/json"
	"testing"

	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/core/types"
)

func TestNativeErrorDespiteSuccessfulReceipt(t *testing.T) {
	purchase := Purchase{Hash: common.HexToHash("0x01"), Owner: common.HexToAddress("0x02")}
	id := common.HexToHash("0x03")
	payload, err := json.Marshal(map[string]interface{}{"Error": "not enough time lock or asset balance", "TicketID": id, "TicketOwner": purchase.Owner})
	if err != nil {
		t.Fatal(err)
	}
	receipt := &types.Receipt{Status: types.ReceiptStatusSuccessful, TxHash: purchase.Hash, Logs: []*types.Log{{Address: common.FSNCallAddress, Topics: []common.Hash{common.BytesToHash([]byte{common.BuyTicketFunc})}, Data: payload}}}
	if err := checkReceipt(receipt, purchase, id); err == nil {
		t.Fatal("successful receipt concealed native execution failure")
	}
}
