// Ported from Mailspring `app/src/components/mail-important-icon.tsx`.
// Adapted seams: `CategoryStore`, `FocusedPerspectiveStore`, `Actions`,
// `ChangeLabelsTask`, `AppEnv` resolve through `./ms-thread` / `./ms-keymap`
// adapters. KIWI has no Important label/category concept in the backend, so
// `getCategoryByRole` honestly returns null and `getState` yields
// `visible: false` — the icon never renders, matching the vendor's
// "no important folder configured" path.
import React from "react";
import _ from "underscore";
import classNames from "classnames";
import { localized } from "./ms-i18n";
import { Actions, CategoryStore, FocusedPerspectiveStore } from "./ms-thread";
import { AppEnv } from "./ms-keymap";
import type { Disposable } from "./ms-keymap";
import type { MsThread } from "./ms-thread";

const ShowImportantKey = "core.workspace.showImportant";

type MailImportantIconProps = {
  thread?: MsThread;
  showIfAvailableForAnyAccount?: boolean;
};
type MailImportantIconState = {
  visible: boolean;
  category: { id: string } | null;
  isImportant: boolean;
};

class MailImportantIcon extends React.Component<MailImportantIconProps, MailImportantIconState> {
  static displayName = "MailImportantIcon";

  unsubscribe?: Disposable;
  subscription?: Disposable;

  constructor(props: MailImportantIconProps) {
    super(props);
    this.state = this.getState();
  }

  getState = (props = this.props) => {
    let category: { id: string } | null = null;
    let visible = false;

    if (props.showIfAvailableForAnyAccount) {
      const perspective = FocusedPerspectiveStore.current();
      for (const accountId of perspective.accountIds) {
        const accountImportant = CategoryStore.getCategoryByRole(accountId, "important");
        if (accountImportant) {
          visible = true;
        }
        if (props.thread && accountId === props.thread.accountId) {
          category = accountImportant;
        }
        if (visible && category) {
          break;
        }
      }
    } else if (props.thread) {
      category = CategoryStore.getCategoryByRole(props.thread.accountId, "important");
      visible = category != null;
    }

    const isImportant =
      (category && props.thread?.labels?.find((x) => x.id === category.id) != null) || false;

    return { visible, category, isImportant };
  };

  componentDidMount() {
    this.unsubscribe = FocusedPerspectiveStore.listen(() => {
      this.setState(this.getState());
    });
    this.subscription = AppEnv.config.onDidChange(ShowImportantKey, () => {
      this.setState(this.getState());
    });
  }

  componentDidUpdate(prevProps: MailImportantIconProps) {
    if (
      prevProps.thread !== this.props.thread ||
      prevProps.showIfAvailableForAnyAccount !== this.props.showIfAvailableForAnyAccount
    ) {
      this.setState(this.getState());
    }
  }

  componentWillUnmount() {
    if (this.unsubscribe) {
      this.unsubscribe.dispose();
    }
    if (this.subscription) {
      this.subscription.dispose();
    }
  }

  shouldComponentUpdate(_nextProps: MailImportantIconProps, nextState: MailImportantIconState) {
    return !_.isEqual(nextState, this.state);
  }

  render() {
    let title;
    if (!this.state.visible) {
      return false;
    }

    const classes = classNames({
      "mail-important-icon": true,
      enabled: this.state.category != null,
      active: this.state.isImportant,
    });

    if (!this.state.category) {
      title = localized("No important folder / label");
    } else if (this.state.isImportant) {
      title = localized("Mark as Not Important");
    } else {
      title = localized("Mark as Important");
    }

    return <div className={classes} title={title} onClick={this._onToggleImportant} />;
  }

  _onToggleImportant = (event: React.MouseEvent) => {
    const { category } = this.state;

    if (category && this.props.thread) {
      const isImportant = this.props.thread.labels?.find((x) => x.id === category.id) != null;
      Actions.queueTask({
        kind: "change-labels",
        labelsToAdd: isImportant ? [] : [category],
        labelsToRemove: isImportant ? [category] : [],
        threads: [this.props.thread],
        source: "Important Icon",
      });
    }

    // Don't trigger the thread row click
    event.stopPropagation();
  };
}

export default MailImportantIcon;
