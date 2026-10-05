// Ported from Mailspring `app/src/components/account-color-bar.tsx`.
// Adapted seam: `AccountStore.accountForId(id).color` → the KIWI account
// color registry in `ms-thread.ts` (seeded from AccountView.color — real
// backend-assigned hues). Unknown account → `<span />` exactly as the
// vendor's missing-account path renders.
import React from "react";
import { accountColorFor, onAccountColorsChanged } from "./ms-thread";

export class AccountColorBar extends React.Component<{ accountId: string }, { color: string | null }> {
  static displayName = "AccountColorBar";

  unsubscribe?: () => void;

  constructor(props: { accountId: string }) {
    super(props);
    this.state = { color: this.getColor(props) };
  }

  getColor = (props = this.props) => {
    return accountColorFor(props.accountId);
  };

  componentDidMount() {
    this.unsubscribe = onAccountColorsChanged(() => {
      const nextColor = this.getColor();
      if (this.state.color !== nextColor) this.setState({ color: nextColor });
    });
  }

  componentWillUnmount() {
    this.unsubscribe && this.unsubscribe();
  }

  render() {
    return this.state.color ? (
      <span
        style={{
          height: "50%",
          paddingLeft: "4px",
          borderLeftWidth: "4px",
          borderLeftColor: this.state.color,
          borderLeftStyle: "solid",
        }}
      />
    ) : (
      <span />
    );
  }
}

export default AccountColorBar;
