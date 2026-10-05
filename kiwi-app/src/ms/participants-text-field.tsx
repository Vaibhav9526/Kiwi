// Ported from Mailspring app/src/components/participants-text-field.tsx
// Seams: 'mailspring-exports' -> './ms-exports' (Contact/ContactGroup/
// ContactStore/localized/Utils/RegExpUtils); unused 'electron' ipcRenderer
// import dropped (noUnusedLocals — it was dead in the vendor file too);
// 'mailspring-component-kit' -> './tokenizing-text-field' + './menu';
// InjectedComponentSet -> inline replacement below (KIWI has no
// ComponentRegistry / plugin loader — the 'Composer:RecipientChip' role is
// always empty, so we render the same empty inline-flex container the vendor
// emits for an empty set); '@electron/remote' Menu/MenuItem/clipboard -> kit
// remote.Menu/MenuItem + clipboard via './ms-exports' (popup coords come from
// the last pointer position — see below); Flux `Message`/`DraftEditingSession`
// prop types -> minimal local shapes (the component never reads them);
// DatabaseStore ContactGroup expansion -> warn-only (KIWI has no contact
// groups; ContactStore.searchContactGroups is always empty).
// Strict-TS: ParticipantField casts for dynamic field indexing
// (`field?: string` kept verbatim on the public props).
import React from 'react';
import {
  localized,
  Utils,
  Contact,
  ContactStore,
  RegExpUtils,
  ContactGroup,
  remote,
  MenuItem,
  clipboard,
} from './ms-exports';
import { TokenizingTextField } from './tokenizing-text-field';
import { Menu } from './menu';

// KIWI seam: `remote.Menu.popup()` in Electron opens at the native cursor
// position; the kit DOM Menu needs explicit x/y. Token context menus are
// always mouse-invoked (the `.action` caret button), so the last mousedown
// position is the cursor position at popup time.
let _lastPointer = { x: 0, y: 0 };
if (typeof document !== 'undefined') {
  document.addEventListener(
    'mousedown',
    (e) => {
      _lastPointer = { x: e.clientX, y: e.clientY };
    },
    true
  );
}

// KIWI seam: vendor rendered components registered for role
// 'Composer:RecipientChip' via Mailspring's ComponentRegistry, inside a
// Flexbox (direction + inline props). KIWI has no plugin registry, so the
// set is permanently empty — this renders the same empty inline-flex
// container the vendor produces for a zero-match set.
const InjectedComponentSet = (props: {
  matching: { role: string };
  exposedProps?: Record<string, unknown>;
  direction?: string;
  inline?: boolean;
}) => (
  <div
    style={{
      display: props.inline ? 'inline-flex' : 'flex',
      flexDirection: props.direction === 'column' ? 'column' : 'row',
    }}
  />
);

const TokenRenderer = (props: { token: object }) => {
  const contact = props.token as Contact;
  let chipText = contact.email;
  if (contact.name && contact.name.length > 0 && contact.name !== contact.email) {
    chipText = contact.fullName();
  }
  return (
    <div className="participant">
      <InjectedComponentSet
        matching={{ role: 'Composer:RecipientChip' }}
        exposedProps={{ contact: props.token, collapsed: false }}
        direction="row"
        inline
      />
      <span className="participant-primary">{chipText}</span>
    </div>
  );
};

// KIWI seam: vendor declared `draft?: Message` and `session?:
// DraftEditingSession`. The component body never reads either — they exist
// so compose.tsx can carry draft context. These minimal shapes keep the
// props on the public API without porting the Flux models.
type ParticipantsDraft = { accountId?: string };
type ParticipantsSession = { draft?: ParticipantsDraft };

// strict-TS seam: vendor indexed `participants`/`updates` with `field`
// (a plain string) under a non-strict tsconfig. Alias the field names.
type ParticipantField = 'to' | 'cc' | 'bcc' | 'replyTo';

type ParticipantsTextFieldProps = {
  field?: string;
  label?: string;
  participants: { to: Contact[]; cc: Contact[]; bcc: Contact[]; replyTo: Contact[] };
  change: (...args: any[]) => any;
  className?: string;
  onEmptied?: (...args: any[]) => any;
  onFocus?: (...args: any[]) => any;
  draft?: ParticipantsDraft;
  session?: ParticipantsSession;
};

export default class ParticipantsTextField extends React.Component<ParticipantsTextFieldProps> {
  static displayName = 'ParticipantsTextField';

  _textfieldEl?: TokenizingTextField<Contact> | null;

  static defaultProps = {
    visible: true,
  };

  shouldComponentUpdate(nextProps: ParticipantsTextFieldProps, nextState: Record<string, unknown>) {
    return !Utils.isEqualReact(nextProps, this.props) || !Utils.isEqualReact(nextState, this.state);
  }

  // Public. Can be called by any component that has a ref to this one to
  // focus the input field.
  focus = () => {
    this._textfieldEl!.focus();
  };

  _completionNode = (
    p: (Contact | ContactGroup) & { customComponent?: React.ComponentType<any> }
  ) => {
    const CustomComponent = p.customComponent;
    if (CustomComponent) return <CustomComponent token={p} />;
    if (p instanceof Contact) {
      return <Menu.NameEmailContent name={p.fullName()} email={p.email} key={p.id} />;
    } else if (p instanceof ContactGroup) {
      return p.name;
    }
  };

  _tokensForString = async (string: string, options: { skipNameLookup?: boolean } = {}) => {
    // If the input is a string, parse out email addresses and build
    // an array of contact objects. For each email address wrapped in
    // parentheses, look for a preceding name, if one exists.
    if (string.length === 0) {
      return [];
    }

    const contacts = await ContactStore.parseContactsInString(string, options);
    if (contacts.length > 0) {
      return contacts;
    }

    // If no contacts are returned, treat the entire string as a single
    // (malformed) contact object.
    // strict-TS seam: vendor passed `name: null`; kit Contact takes `name?: string`
    // — omitting yields the same falsy name.
    return [new Contact({ email: string })];
  };

  _remove = (values: (string | Contact)[]) => {
    const field = this.props.field as ParticipantField;
    const updates: Partial<Record<ParticipantField, Contact[]>> = {};
    updates[field] = this.props.participants[field].filter(
      (p) =>
        !(
          values.includes(p.email) ||
          values.map((o) => (typeof o === 'string' ? o : o.email)).includes(p.email)
        )
    );
    this.props.change(updates);
  };

  _edit = async (token: Contact, replacementString: string) => {
    const field = this.props.field as ParticipantField;
    const tokenIndex = this.props.participants[field].indexOf(token);

    const replacements = await this._tokensForString(replacementString);
    const updates: Partial<Record<ParticipantField, Contact[]>> = {};
    updates[field] = [...this.props.participants[field]];
    updates[field]!.splice(tokenIndex, 1, ...replacements);
    this.props.change(updates);
  };

  _add = (
    values: string | (Contact | ContactGroup)[],
    options: { skipNameLookup?: boolean } = {}
  ) => {
    // It's important we return here (as opposed to ignoring the
    // `this.props.change` callback) because this method is asynchronous.

    // The `tokensPromise` may be formed with an empty draft, but resolved
    // after a draft was prepared. This would cause the bad data to be
    // propagated.

    // If the input is a string, parse out email addresses and build
    // an array of contact objects. For each email address wrapped in
    // parentheses, look for a preceding name, if one exists.
    let tokensPromise: Promise<(Contact | ContactGroup)[]>;
    if (typeof values === 'string') {
      tokensPromise = this._tokensForString(values, options);
    } else {
      tokensPromise = Promise.resolve(values);
    }

    tokensPromise.then(async (tokens) => {
      // Safety check: remove anything from the incoming tokens that isn't
      // a Contact. We should never receive anything else in the tokens array.
      const contactTokens = tokens.filter((value) => value instanceof Contact);
      const groupTokens = tokens.filter((value) => value instanceof ContactGroup);

      // KIWI seam: vendor expanded group tokens into their member contacts via
      //   DatabaseStore.findAll<Contact>(Contact, [
      //     Contact.attributes.contactGroups.containsAny(groupTokens.map((g) => g.id)),
      //   ]);
      // KIWI has no contact-group membership source (searchContactGroups is
      // always empty), so group tokens should never arrive — warn instead of
      // silently dropping them if they somehow do.
      if (groupTokens.length > 0) {
        console.warn(
          'ParticipantsTextField: ContactGroup tokens cannot be expanded — KIWI has no contact groups',
          groupTokens
        );
      }

      const updates: Partial<Record<ParticipantField, Contact[]>> = {};
      for (const field of Object.keys(this.props.participants) as ParticipantField[]) {
        updates[field] = [...this.props.participants[field]];
      }

      const targetField = this.props.field as ParticipantField;
      for (const token of contactTokens) {
        // first remove the participant from all the fields. This ensures
        // that drag and drop isn't "drag and copy." and you can't have the
        // same recipient in multiple places.
        for (const field of Object.keys(this.props.participants) as ParticipantField[]) {
          updates[field] = updates[field]!.filter((p) => p.email !== token.email);
        }

        // add the participant to field
        updates[targetField] = [...updates[targetField]!, token];
      }

      this.props.change(updates);
    });

    return '';
  };

  _onShowContextMenu = (participant: Contact) => {
    // KIWI seam: '@electron/remote' Menu/MenuItem/clipboard -> kit remote.Menu,
    // MenuItem and clipboard from './ms-exports'. Electron popup() opens at
    // the cursor; the kit DOM popup needs explicit coords (_lastPointer).
    const menu = new remote.Menu();
    menu.items.push(
      new MenuItem({
        label: `${localized(`Copy`)} ${participant.email}`,
        click: () => {
          clipboard.writeText(participant.email);
        },
      })
    );
    menu.items.push(
      new MenuItem({
        type: 'separator',
      })
    );
    menu.items.push(
      new MenuItem({
        label: localized('Remove'),
        click: () => this._remove([participant]),
      })
    );
    menu.popup({ x: _lastPointer.x, y: _lastPointer.y });
  };

  _onInputTrySubmit = (
    inputValue: string,
    completions: (Contact | ContactGroup)[] = [],
    selectedItem: Contact | ContactGroup | null
  ) => {
    if (RegExpUtils.emailRegex().test(inputValue)) {
      return inputValue; // no token default to raw value.
    }
    return selectedItem || completions[0]; // first completion if any
  };

  _shouldBreakOnKeydown = (event: React.KeyboardEvent<HTMLInputElement>) => {
    const val = (event.target as HTMLInputElement).value.trim();
    if (RegExpUtils.emailRegex().test(val) && event.key === ' ') {
      return true;
    }
    return [',', ';'].includes(event.key);
  };

  render() {
    return (
      <div className={this.props.className}>
        <TokenizingTextField<Contact>
          ref={(el) => {
            this._textfieldEl = el;
          }}
          tokens={this.props.participants[this.props.field as ParticipantField]}
          tokenKey={(p) => p.email || p.id}
          tokenIsValid={(p) => ContactStore.isValidContact(p)}
          tokenRenderer={TokenRenderer}
          onRequestCompletions={async (input) =>
            // strict-TS seam: vendor flowed (Contact | ContactGroup)[] through
            // here relying on loose typing. KIWI's searchContactGroups is
            // always empty, so the union is Contact[] in practice.
            ((await Promise.all([
              ContactStore.searchContactGroups(input),
              ContactStore.searchContacts(input),
            ])).flat() as Contact[])
          }
          shouldBreakOnKeydown={this._shouldBreakOnKeydown}
          onInputTrySubmit={this._onInputTrySubmit}
          completionNode={this._completionNode}
          onAdd={this._add}
          onRemove={this._remove}
          onEdit={this._edit}
          onEmptied={this.props.onEmptied}
          onFocus={this.props.onFocus}
          onTokenAction={this._onShowContextMenu}
          className={this.props.field}
          label={this.props.label}
        />
      </div>
    );
  }
}
