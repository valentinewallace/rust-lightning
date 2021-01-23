A crate to test MPP #646.

To run:
`cargo run` from the `testmpp` crate directory.

What it does is connect to ~25-30 mainnet peers, sync the routing graph with
them, then tries to find a route to a specific node.

To change the number of paths the program is aiming to get: change
`num_active_nodes` 
To change the split payment amount, change `payment_amt_msat`.
To change the payee node, change `dest_pk` on line 203.

Each node gets `payment_amt_msat` multiplied by a scaling factor, divided
by `num_active_nodes` in outbound liquidity. This is because we want to force it
to choose multiple paths, so we limit the amount of outbound each node has.

The scaling factor (currently 1.2 on line 21) gives each node a little more
outbound than they should need to forward the payment.
