package trustclient_test

import (
	"context"
	"fmt"

	"github.com/Darren-Certlocker/trust-go-client"
)

func ExampleNewBuilder() {
	client, err := trustclient.NewBuilder().
		URL("https://trust.certlocker.io").
		AccountID("acct-1").
		APIToken("ui-minted-token").
		Build(context.Background())
	if err != nil {
		fmt.Println("error")
		return
	}
	defer client.Close()
	fmt.Println(client.AccountID())
	// Output:
	// acct-1
}

func ExampleAudienceForAccount() {
	audience, err := trustclient.AudienceForAccount("acct-1")
	if err != nil {
		fmt.Println("error")
		return
	}
	fmt.Println(audience)
	// Output:
	// https://trust.certlocker.io/oidc/acct-1
}
