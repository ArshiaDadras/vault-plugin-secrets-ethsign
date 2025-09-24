package backend

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathSign(b *backend) *framework.Path {
	return &framework.Path{
		Pattern:      "accounts/" + framework.GenericNameRegex("name") + "/sign",
		HelpSynopsis: "Sign a provided transaction object.",
		HelpDescription: `

    Sign a transaction object with properties conforming to the Ethereum JSON-RPC documentation.

    `,
		Fields: map[string]*framework.FieldSchema{
			"name": {Type: framework.TypeString},
			"to": {
				Type:        framework.TypeString,
				Description: "(optional when creating new contract) The contract address the transaction is directed to.",
				Default:     "",
			},
			"data": {
				Type:        framework.TypeString,
				Description: "The compiled code of a contract OR the hash of the invoked method signature and encoded parameters.",
			},
			"input": {
				Type:        framework.TypeString,
				Description: "The compiled code of a contract OR the hash of the invoked method signature and encoded parameters.",
			},
			"value": {
				Type:        framework.TypeString,
				Description: "Integer of the value sent with this transaction (in wei).",
			},
			"nonce": {
				Type:        framework.TypeString,
				Description: "The transaction nonce.",
			},
			"gas": {
				Type:        framework.TypeString,
				Description: "Integer of the gas provided for the transaction execution. It will return unused gas",
			},
			"gasPrice": {
				Type:        framework.TypeString,
				Description: "(optional) The gas price for legacy transactions in wei. Mutually exclusive with maxFeePerGas/maxPriorityFeePerGas.",
			},
			"maxFeePerGas": {
				Type:        framework.TypeString,
				Description: "(optional) Maximum fee per gas for EIP-1559 transactions in wei. Used with maxPriorityFeePerGas for EIP-1559 transactions.",
			},
			"maxPriorityFeePerGas": {
				Type:        framework.TypeString,
				Description: "(optional) Maximum priority fee per gas (tip) for EIP-1559 transactions in wei. Used with maxFeePerGas for EIP-1559 transactions.",
			},
			"chainId": {
				Type:        framework.TypeString,
				Description: "(optional) Chain ID of the target blockchain network. If present, EIP155 signer will be used to sign. If omitted, Homestead signer will be used.",
				Default:     "0",
			},
		},
		ExistenceCheck: b.pathExistenceCheck,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.signTx,
		},
	}
}
