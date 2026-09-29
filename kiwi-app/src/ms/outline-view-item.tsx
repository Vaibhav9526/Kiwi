/* eslint global-require:0 */

/* Ported from Mailspring `app/src/components/outline-view-item.tsx` — logic
 * verbatim; adapted seams:
 *   - `mailspring-exports` → `./ms-exports` (Utils, localized)
 *   - `RetinaImg` → `./retina-img` (Icon-registry adapter, Mode kept)
 *   - `require('@electron/remote')` Menu/MenuItem → `./ms-electron` kit
 *     (`menu.append(item)` → `menu.items.push(item)`; `.popup({})` gets
 *     explicit {x, y} since the DOM menu can't auto-position at the cursor)
 *   - `ReactDOM.findDOMNode` → named `findDOMNode` import + instanceof guard
 *   - `_expandTimeout` typed `ReturnType<typeof setTimeout>` (no NodeJS types)
 *   - `item.count`/`item.className` guarded for strict optionals
 *   - KIWI seams (IOutlineViewItem, declared in ./outline-view):
 *       * `onContextMenu` — when set, right-click + the "•••" button delegate
 *         to the host menu instead of the built-in Electron menu
 *       * `shouldDenyDrop` + `state.dropDenied` — hover affordance for
 *         refused drops (em-drop-denied / aria-dropeffect="none")
 *       * `rowAttrs` — data-X/aria-X spread onto the `.item` row element
 *       * dragover/dragleave/drop bookkeeping on the treeitem wrapper feeds
 *         the em-drop-target/em-drop-denied classes (the suites fire
 *         `dragover` without `dragenter`, and DropZone's counter can't paint
 *         a denial); handlers are owner-guarded so nested items don't bleed
 *       * click selection moved to the treeitem wrapper (owner-guarded) so a
 *         click dispatched on [role=treeitem] selects — upstream had it on
 *         the inner .item only
 *       * `.icon`/`.name`/`.item-count-box` also carry em-tree-icon /
 *         em-tree-label / em-tree-count for the existing KIWI theme hooks
 */
import { Utils, localized } from './ms-exports';
import classnames from 'classnames';
import React, { Component } from 'react';
import { findDOMNode } from 'react-dom';
import { Menu, MenuItem } from './ms-electron';
import type { MenuItemOptions } from './ms-electron';
import { DisclosureTriangle } from './disclosure-triangle';
import { DropZone } from './drop-zone';
import { RetinaImg } from './retina-img';
import type { IOutlineViewItem } from './outline-view';

/*
 * Enum for counter styles
 * @readonly
 * @enum {string}
 */
const CounterStyles = {
  Default: 'def',
  Alt: 'alt',
};

type OutlineViewItemProps = {
  item: IOutlineViewItem;
  level?: number;
  isFirst?: boolean;
  sectionTitle?: string;
};
type OutlineViewItemState = {
  editing: boolean;
  isDropping: boolean;
  dropDenied: boolean;
  creatingChild: boolean;
};
/*
 * Renders an item that may contain more arbitrarily nested items
 * This component resembles OS X's default OutlineView or Sourcelist
 *
 * An OutlineViewItem behaves like a controlled React component; it controls no
 * state internally. All of the desired state must be passed in through props.
 *
 *
 * OutlineView handles:
 * - Collapsing and uncollapsing
 * - Editing value for item
 * - Deleting item
 * - Selecting the item
 * - Displaying an associated count
 * - Dropping elements
 *
 * @param {object} props - props for OutlineViewItem
 * @param {object} props.item - props for OutlineViewItem
 * @param {string} props.item.id - Unique id for the item.
 * @param {string} props.item.name - Name to display
 * @param {string} props.item.contextMenuLabel - Label to be displayed in context menu
 * @param {string} props.item.className - Extra classes to add to the item
 * @param {string} props.item.iconName - Icon name for icon. See {@link RetinaImg} for further reference.
 * @param {array} props.item.children - Array of children of the same type to be
 * displayed.
 * @param {number} props.item.count - Count to display. If falsy, wont display a
 * count.
 * @param {CounterStyles} props.item.counterStyle - One of the possible
 * CounterStyles
 * @param {string} props.item.inputPlaceholder - Placehodler to use when editing
 * item
 * @param {boolean} props.item.collapsed - Whether the OutlineViewItem is collapsed or
 * not
 * @param {boolean} props.item.editing - Whether the OutlineViewItem is being
 * edited
 * @param {boolean} props.item.selected - Whether the OutlineViewItem is selected
 * @param {props.item.shouldAcceptDrop} props.item.shouldAcceptDrop
 * @param {props.item.onCollapseToggled} props.item.onCollapseToggled
 * @param {props.item.onInputCleared} props.item.onInputCleared
 * @param {props.item.onDrop} props.item.onDrop
 * @param {props.item.onSelect} props.item.onSelect
 * @param {props.item.onDelete} props.item.onDelete
 * @param {props.item.onEdited} props.item.onEdited
 * @class OutlineViewItem
 */
class OutlineViewItem extends Component<OutlineViewItemProps, OutlineViewItemState> {
  static displayName = 'OutlineView';

  /*
   * If provided, this function will be called when receiving a drop. It must
   * return true if it should accept it or false otherwise.
   * @callback props.item.shouldAcceptDrop
   * @param {object} item - The current item
   * @param {object} event - The drag event
   * @return {boolean}
   */
  /*
   * If provided, this function will be called when the action to collapse or
   * uncollapse the OutlineViewItem is executed.
   * @callback props.item.onCollapseToggled
   * @param {object} item - The current item
   */
  /*
   * If provided, this function will be called when the editing input is cleared
   * via Esc key, blurring, or submiting the edit.
   * @callback props.item.onInputCleared
   * @param {object} item - The current item
   * @param {object} event - The associated event
   */
  /*
   * If provided, this function will be called when an element is dropped in the
   * item
   * @callback props.item.onDrop
   * @param {object} item - The current item
   * @param {object} event - The associated event
   */
  /*
   * If provided, this function will be called when the item is selected
   * @callback props.item.onSelect
   * @param {object} item - The current item
   */
  /*
   * If provided, this function will be called when the the delete action is
   * executed
   * @callback props.item.onDelete
   * @param {object} item - The current item
   */
  /*
   * If provided, this function will be called when the item is edited
   * @callback props.item.onEdited
   * @param {object} item - The current item
   * @param {string} value - The new value
   */
  static CounterStyles = CounterStyles;

  _expandTimeout?: ReturnType<typeof setTimeout> | null;

  constructor(props: OutlineViewItemProps) {
    super(props);
    this.state = {
      isDropping: false,
      dropDenied: false,
      editing: props.item.editing || false,
      creatingChild: false,
    };
  }

  componentDidMount() {
    if (this._shouldShowContextMenu()) {
      const node = findDOMNode(this);
      if (node instanceof Element) {
        node.addEventListener('contextmenu', this._onShowContextMenu);
      }
    }
  }

  componentDidUpdate(prevProps: OutlineViewItemProps) {
    if (this.props.item.editing && !prevProps.item.editing) {
      this.setState({ editing: this.props.item.editing });
    }
  }

  shouldComponentUpdate(nextProps: OutlineViewItemProps, nextState: OutlineViewItemState) {
    return !Utils.isEqualReact(nextProps, this.props) || !Utils.isEqualReact(nextState, this.state);
  }

  componentWillUnmount() {
    clearTimeout(this._expandTimeout ?? undefined);
    if (this._shouldShowContextMenu()) {
      const node = findDOMNode(this);
      if (node instanceof Element) {
        node.removeEventListener('contextmenu', this._onShowContextMenu);
      }
    }
  }

  // Helpers

  _runCallback = (method: keyof IOutlineViewItem, ...args: unknown[]) => {
    const item = this.props.item;
    const fn = item[method];
    if (typeof fn === 'function') {
      return fn(item, ...args);
    }
    return undefined;
  };

  _shouldShowContextMenu = () => {
    return (
      this.props.item.onDelete != null ||
      this.props.item.onEdited != null ||
      this.props.item.onExport != null ||
      this.props.item.onExportMbox != null ||
      this.props.item.onCreateChild != null ||
      this.props.item.onMarkAllAsRead != null ||
      this.props.item.onContextMenu != null
    );
  };

  _shouldAcceptDrop = (event: React.DragEvent) => {
    return this._runCallback('shouldAcceptDrop', event);
  };

  _clearEditingState = (event: React.SyntheticEvent) => {
    this.setState({ editing: false });
    this._runCallback('onInputCleared', event);
  };

  // Handlers

  _onDragStateChange = ({ isDropping }: { isDropping: boolean }) => {
    this.setState({ isDropping });

    const { item } = this.props;
    if (isDropping === true && item.children.length > 0 && item.collapsed) {
      this._expandTimeout = setTimeout(this._onCollapseToggled, 650);
    } else if (isDropping === false && this._expandTimeout) {
      clearTimeout(this._expandTimeout ?? undefined);
      this._expandTimeout = null;
    }
  };

  _onDrop = (event: React.DragEvent) => {
    this.setState({ isDropping: false, dropDenied: false });
    this._runCallback('onDrop', event);
  };

  /* KIWI seam handlers — the treeitem wrapper watches bubbled drag events so
   * the hover affordance (em-drop-target / em-drop-denied + aria-dropeffect)
   * reflects the item's verdict even when the DropZone counter never engaged
   * (synthetic drags fire dragover without dragenter) and so refused drags
   * can paint an honest denial. An event "belongs" to this row only when it
   * lands on the row itself or inside its own `.item-container` — targets in
   * `.item-children` belong to the child rows nested there. */
  _ownsDomEvent = (event: { target: EventTarget | null; currentTarget: EventTarget | null }) => {
    const target = event.target;
    const host = event.currentTarget;
    if (!(target instanceof HTMLElement) || !(host instanceof HTMLElement)) return false;
    if (target === host) return true;
    const own = host.querySelector(':scope > .item-container');
    return own?.contains(target) === true;
  };

  _onItemDragOver = (event: React.DragEvent<HTMLDivElement>) => {
    if (!this._ownsDomEvent(event)) return;
    const dropping = !!this._runCallback('shouldAcceptDrop', event);
    const denied = !dropping && !!this._runCallback('shouldDenyDrop', event);
    /* DropZone's dragover already preventDefaulted; the dropEffect write
     * here is the last word before paint so a refused drop shows the honest
     * 'none' affordance and an accepted message move shows 'move'. */
    if (denied) event.dataTransfer.dropEffect = 'none';
    else if (dropping) event.dataTransfer.dropEffect = 'move';
    if (dropping !== this.state.isDropping || denied !== this.state.dropDenied) {
      this.setState({ isDropping: dropping, dropDenied: denied });
    }
  };

  _onItemDragLeave = (event: React.DragEvent<HTMLDivElement>) => {
    if (!this._ownsDomEvent(event)) return;
    if (this.state.dropDenied) this.setState({ dropDenied: false });
  };

  _onItemDropDone = (event: React.DragEvent<HTMLDivElement>) => {
    // Denied drops never reach DropZone._onDrop (it refuses before calling
    // onDrop) — they bubble to the treeitem, so clear the denial here.
    if (!this._ownsDomEvent(event)) return;
    if (this.state.dropDenied) this.setState({ dropDenied: false });
  };

  _onCollapseToggled = () => {
    this._runCallback('onCollapseToggled');
  };

  _onClick = (event: React.MouseEvent) => {
    // Bound on the treeitem wrapper (KIWI seam): a synthetic .click() on the
    // treeitem — and clicks anywhere inside .item — must still select. The
    // owner guard keeps a nested child item's click from also selecting this
    // row; the disclosure-triangle guard keeps collapse clicks from
    // selecting (upstream had onClick on .item, a triangle sibling).
    const target = event.target;
    if (
      !(
        this._ownsDomEvent(event) &&
        target instanceof HTMLElement &&
        !target.closest('.disclosure-triangle')
      )
    ) {
      return;
    }
    event.preventDefault();
    this._runCallback('onSelect');
  };

  _onDelete = () => {
    this._runCallback('onDelete');
  };

  _onEdited = (value: string) => {
    this._runCallback('onEdited', value);
  };

  _onEdit = () => {
    if (this.props.item.onEdited) {
      this.setState({ editing: true });
    }
  };

  _onCreateChildTriggered = () => {
    if (this.props.item.collapsed) {
      this._onCollapseToggled();
    }
    this.setState({ creatingChild: true });
  };

  _onChildCreated = (_item: IOutlineViewItem, value: string) => {
    this.setState({ creatingChild: false });
    if (value) {
      this._runCallback('onCreateChild', value);
    }
  };

  _onCreateChildInputCleared = () => {
    this.setState({ creatingChild: false });
  };

  _onInputFocus = (event: React.FocusEvent<HTMLInputElement>) => {
    const input = event.target;
    input.selectionStart = input.selectionEnd = input.value.length;
  };

  _onInputBlur = (event: React.FocusEvent<HTMLInputElement>) => {
    this._clearEditingState(event);
  };

  _onInputKeyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Escape') {
      this._clearEditingState(event);
    }
    if (['Enter', 'Return'].includes(event.key)) {
      this._onEdited((event.target as HTMLInputElement).value);
      this._clearEditingState(event);
    }
  };

  _buildContextMenu = () => {
    const item = this.props.item;
    const contextMenuLabel = item.contextMenuLabel || item.name;
    const isLabel = (contextMenuLabel ?? '').toLowerCase() === 'label';

    // Groups: act on contents, organize the folder itself (destructive last), export.
    const groups: (MenuItemOptions | undefined)[][] = [
      [
        item.onMarkAllAsRead && {
          label: localized('Mark All as Read'),
          click: () => this._runCallback('onMarkAllAsRead'),
        },
      ],
      [
        item.onCreateChild && {
          label: isLabel ? localized(`New Sublabel...`) : localized(`New Subfolder...`),
          click: this._onCreateChildTriggered,
        },
        item.onEdited && {
          label: `${localized(`Rename`)} ${contextMenuLabel}`,
          click: this._onEdit,
        },
        item.onDelete && {
          label: `${localized(`Delete`)} ${contextMenuLabel}`,
          click: this._onDelete,
        },
      ],
      [
        item.onExport && {
          label: localized(`Export folder as .eml files...`),
          click: () => this._runCallback('onExport'),
        },
        item.onExportMbox && {
          label: localized(`Export folder as .mbox file...`),
          click: () => this._runCallback('onExportMbox'),
        },
      ],
    ];

    const menu = new Menu();
    for (const group of groups) {
      const entries = group.filter((entry): entry is MenuItemOptions => !!entry);
      if (entries.length === 0) continue;
      if (menu.items.length > 0) menu.items.push(new MenuItem({ type: 'separator' }));
      entries.forEach((entry) => menu.items.push(new MenuItem(entry)));
    }
    return menu;
  };

  _onShowContextMenu = (event: Event) => {
    event.stopPropagation();
    if (this.props.item.onContextMenu) {
      this._runCallback('onContextMenu', event);
      return;
    }
    const mouse = event as MouseEvent;
    this._buildContextMenu().popup({ x: mouse.clientX, y: mouse.clientY });
  };

  _onMenuButtonClick = (event: React.MouseEvent) => {
    event.stopPropagation();
    if (this.props.item.onContextMenu) {
      this._runCallback('onContextMenu', event);
      return;
    }
    this._buildContextMenu().popup({ x: event.clientX, y: event.clientY });
  };

  // Renderers

  _renderItem(item: IOutlineViewItem = this.props.item, state: OutlineViewItemState = this.state) {
    const containerClass = classnames({
      item: true,
      selected: item.selected,
      editing: state.editing,
      'em-drop-target': state.isDropping,
      'em-drop-denied': state.dropDenied,
      [item.className as string]: item.className,
    });

    return (
      <DropZone
        {...item.rowAttrs}
        id={item.id}
        className={containerClass}
        aria-dropeffect={state.isDropping ? 'move' : state.dropDenied ? 'none' : undefined}
        onDrop={this._onDrop}
        onDoubleClick={this._onEdit}
        shouldAcceptDrop={this._shouldAcceptDrop}
        onDragStateChange={this._onDragStateChange}
      >
        {(item.count ?? 0) > 0 && (
          <div
            className={`item-count-box em-tree-count ${item.counterStyle === CounterStyles.Alt && 'alt-count'}`}
          >
            {item.count}
          </div>
        )}
        {item.iconName && (
          <div className="icon em-tree-icon">
            <RetinaImg
              name={item.iconName}
              fallback={'folder.png'}
              mode={RetinaImg.Mode.ContentIsMask}
            />
          </div>
        )}
        {state.editing ? (
          <input
            autoFocus
            type="text"
            tabIndex={0}
            className="item-input"
            placeholder={item.inputPlaceholder || ''}
            defaultValue={item.name}
            onBlur={this._onInputBlur}
            onFocus={this._onInputFocus}
            onKeyDown={this._onInputKeyDown}
          />
        ) : (
          <div className="name em-tree-label" title={item.name}>
            {item.name}
          </div>
        )}
        {this._shouldShowContextMenu() && !state.editing && this.props.item.onEdited && (
          <div
            className="item-action-button"
            role="button"
            tabIndex={-1}
            aria-label={localized('Actions')}
            onClick={this._onMenuButtonClick}
          >
            •••
          </div>
        )}
      </DropZone>
    );
  }

  _renderCreateChildInput() {
    const isLabel = (this.props.item.contextMenuLabel || '').toLowerCase() === 'label';
    const item: IOutlineViewItem = {
      id: `create-child-${this.props.item.id}`,
      name: '',
      children: [],
      editing: true,
      iconName: this.props.item.iconName || 'folder.png',
      onEdited: this._onChildCreated,
      inputPlaceholder: isLabel ? localized('Sublabel name') : localized('Subfolder name'),
      onInputCleared: this._onCreateChildInputCleared,
    };
    return <OutlineViewItem item={item} level={(this.props.level || 1) + 1} />;
  }

  _renderChildren(item: IOutlineViewItem = this.props.item) {
    const showRegularChildren = item.children.length > 0 && !item.collapsed;
    const showCreateChildInput = this.state.creatingChild;

    if (showRegularChildren || showCreateChildInput) {
      const childLevel = (this.props.level || 1) + 1;
      return (
        <div role="group" className="item-children" key={`${item.id}-children`}>
          {showCreateChildInput && this._renderCreateChildInput()}
          {showRegularChildren &&
            item.children.map((child) => (
              <OutlineViewItem key={child.id} item={child} level={childLevel} />
            ))}
        </div>
      );
    }
    return <span />;
  }

  render() {
    const item = this.props.item;
    const hasChildren = item.children.length > 0;
    const showAsExpanded = this.state.creatingChild;
    const containerClasses = classnames({
      'item-container': true,
      dropping: this.state.isDropping,
    });
    return (
      <div
        role="treeitem"
        aria-level={this.props.level || 1}
        aria-selected={item.selected || false}
        aria-expanded={
          hasChildren || showAsExpanded ? !(item.collapsed && !showAsExpanded) : undefined
        }
        aria-label={
          this.props.sectionTitle ? `${this.props.sectionTitle}, ${item.name}` : item.name
        }
        tabIndex={item.selected || this.props.isFirst ? 0 : -1}
        onClick={this._onClick}
        onDragOver={this._onItemDragOver}
        onDragLeave={this._onItemDragLeave}
        onDrop={this._onItemDropDone}
      >
        <span className={containerClasses}>
          <DisclosureTriangle
            collapsed={item.collapsed && !showAsExpanded}
            visible={hasChildren || showAsExpanded}
            onCollapseToggled={this._onCollapseToggled}
          />
          {this._renderItem()}
        </span>
        {this._renderChildren()}
      </div>
    );
  }
}

export default OutlineViewItem;
