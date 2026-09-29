// Ported from Mailspring `app/src/components/list-tabular.tsx` —
// `ListTabularColumn` + `ListTabularRows` verbatim.
//
// Seams adapted: `mailspring-exports` → `./ms-exports`, `./list-tabular-item`
// → `./ms-list-tabular-item`.
//
// NOT ported (recorded skin-port decision): the windowed `ListTabular`
// container class, `ScrollRegion`, `ListDataSource`, and `ListSelection`.
// KIWI's mailbox renders the full loaded page (bounded fetches) and the UI
// gates assert `.em-row` counts equal the loaded list — a virtualized
// container would render only the viewport slice and break that contract.
// KIWI's own `.em-rows` listbox + date groups therefore stay the container
// and drive `ListTabularRows` per date group with explicit metrics.
import React, { CSSProperties } from "react";
import { Utils } from "./ms-exports";
import { ListTabularItem } from "./ms-list-tabular-item";

export class ListTabularColumn {
  name: string;
  flex?: number;
  width?: number;
  resolver: any;

  constructor({
    name,
    resolver,
    flex,
    width,
  }: {
    name: string;
    flex?: number;
    width?: number;
    resolver: any;
  }) {
    this.name = name;
    this.resolver = resolver;
    this.flex = flex;
    this.width = width;
  }
}

export type ListTabularRowsProps = {
  rows?: any[];
  columns: any[];
  draggable?: boolean;
  itemHeight?: number;
  innerStyles?: CSSProperties;
  role?: string;
  ariaLabel?: string;
  ariaMultiselectable?: boolean;
  tabIndex?: number;
  ariaActiveDescendant?: string;
  domRef?: (el: HTMLElement | null) => void;
  onSelect?: (...args: any[]) => any;
  onClick?: (...args: any[]) => any;
  onDoubleClick?: (...args: any[]) => any;
  onDragStart?: (...args: any[]) => any;
  onDragEnd?: (...args: any[]) => any;
};

export const ListTabularRows: React.FC<ListTabularRowsProps> = React.memo(
  ({
    rows,
    columns,
    itemHeight,
    innerStyles,
    draggable,
    role,
    ariaLabel,
    ariaMultiselectable,
    tabIndex,
    ariaActiveDescendant,
    domRef,
    onClick,
    onSelect,
    onDoubleClick,
    onDragStart,
    onDragEnd,
  }) => (
    <div
      ref={domRef}
      className="list-rows"
      style={innerStyles}
      onDragStart={onDragStart}
      onDragEnd={onDragEnd}
      draggable={draggable}
      role={role}
      aria-label={ariaLabel}
      aria-multiselectable={ariaMultiselectable}
      tabIndex={tabIndex}
      aria-activedescendant={ariaActiveDescendant}
    >
      {(rows ?? []).map(({ item, idx, itemProps = {} }) => {
        if (!item) return null;
        return (
          <ListTabularItem
            key={item.id || idx}
            item={item}
            itemProps={itemProps}
            metrics={{ top: (idx as number) * (itemHeight ?? 0), height: itemHeight ?? 0 }}
            columns={columns}
            onSelect={onSelect}
            onClick={onClick}
            onDoubleClick={onDoubleClick}
          />
        );
      })}
    </div>
  ),
  (prev, next) => Utils.isEqualReact(prev, next)
);
ListTabularRows.displayName = "ListTabularRows";
