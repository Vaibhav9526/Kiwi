// Ported from Mailspring `app/src/components/list-tabular-item.tsx` —
// verbatim class + render structure.
//
// Seams adapted:
//  - `./swipe-container` → `./ms-swipe-container`.
//  - `itemProps.rowProps` (optional) is spread onto the inner `.list-item`
//    div — KIWI's row contract (`draggable`, `onDragStart`, `onContextMenu`,
//    `onKeyDown`, `tabIndex`, `data-*`) must live on the same element that
//    carries the row class/id/aria hooks; the vendor spreads leftovers on
//    the swipe wrapper instead, which would detach them from `.em-row`.
import SwipeContainer from "./ms-swipe-container";
import React from "react";
import { Utils } from "./ms-exports";
import { ListTabularColumn } from "./ms-list-tabular";

type ListTabularItemProps = {
  metrics?: {
    top: number;
    height: number;
  };
  columns: ListTabularColumn[];
  item: any; // template type soon?
  itemProps?: {
    className?: string;
    role?: string;
    id?: string;
    ariaSelected?: boolean;
    ariaLabel?: string;
    /** KIWI seam: DOM props for the inner .list-item row element. */
    rowProps?: React.HTMLAttributes<HTMLElement>;
  };
  onSelect?: (...args: any[]) => any;
  onClick?: (...args: any[]) => any;
  onDoubleClick?: (...args: any[]) => any;
};

export class ListTabularItem extends React.Component<ListTabularItemProps> {
  static displayName = "ListTabularItem";

  _columnCache: JSX.Element[] | null = null;
  _lastClickTime: number | null = null;

  // DO NOT DELETE unless you know what you're doing! This method cuts
  // React.Perf.wasted-time from ~300msec to 20msec by doing a deep
  // comparison of props before triggering a re-render.
  shouldComponentUpdate(nextProps: ListTabularItemProps, _nextState: Record<string, unknown>) {
    if (
      !Utils.isEqualReact(this.props.item, nextProps.item) ||
      this.props.columns !== nextProps.columns
    ) {
      this._columnCache = null;
      return true;
    }
    if (
      !Utils.isEqualReact(Utils.fastOmit(this.props, ["item"]), Utils.fastOmit(nextProps, ["item"]))
    ) {
      return true;
    }
    return false;
  }

  render() {
    const itemProps = this.props.itemProps || {};
    const className = `list-item list-tabular-item ${itemProps.className ?? ""}`;
    const { role, id, ariaSelected, ariaLabel, rowProps } = itemProps;
    const props = Utils.fastOmit(itemProps, [
      "className",
      "role",
      "id",
      "ariaSelected",
      "ariaLabel",
      "rowProps",
    ]);

    // It's expensive to compute the contents of columns (format timestamps, etc.)
    // We only do it if the item prop has changed.
    if (this._columnCache == null) {
      this._columnCache = this._columns();
    }

    return (
      <SwipeContainer
        {...props}
        role="presentation"
        onClick={this._onClick}
        style={{
          position: "absolute",
          top: this.props.metrics?.top ?? 0,
          width: "100%",
          height: this.props.metrics?.height ?? 0,
        }}
      >
        <div
          className={className}
          style={{ height: this.props.metrics?.height }}
          role={role}
          id={id}
          aria-selected={ariaSelected}
          aria-label={ariaLabel}
          {...rowProps}
        >
          {this._columnCache}
        </div>
      </SwipeContainer>
    );
  }

  _columns = () => {
    const names: Record<string, boolean> = {};
    return (this.props.columns || []).map((column) => {
      if (names[column.name]) {
        console.warn(
          `ListTabular: Columns do not have distinct names, will cause React error! \`${column.name}\` twice.`
        );
      }
      names[column.name] = true;

      return (
        <div
          key={column.name}
          style={{ flex: column.flex, width: column.width }}
          className={`list-column list-column-${column.name}`}
        >
          {column.resolver(this.props.item, this)}
        </div>
      );
    });
  };

  _onClick = (event: React.MouseEvent) => {
    if (typeof this.props.onSelect === "function") {
      this.props.onSelect(this.props.item, event);
    }

    if (typeof this.props.onClick === "function") {
      this.props.onClick(this.props.item, event);
    }
    if (this._lastClickTime != null && Date.now() - this._lastClickTime < 350) {
      if (typeof this.props.onDoubleClick === "function") {
        this.props.onDoubleClick(this.props.item, event);
      }
    }

    this._lastClickTime = Date.now();
  };
}
