( function () {
	'use strict';
	var cfg = window.BeeMonitorAdmin;
	if ( ! cfg ) {
		return;
	}

	function format( str, args ) {
		var i = 0;
		return str.replace( /%(\d+)\$[sd]/g, function ( m, n ) {
			return args[ parseInt( n, 10 ) - 1 ];
		} ).replace( /%[sd]/g, function () {
			return args[ i++ ];
		} );
	}

	var selectAll = document.querySelector( '.bee-monitor-select-all' );
	if ( selectAll ) {
		selectAll.addEventListener( 'change', function () {
			document.querySelectorAll( 'input[name="ids[]"]' ).forEach( function ( box ) {
				box.checked = selectAll.checked;
			} );
		} );
	}

	document.querySelectorAll( '[data-bee-monitor-confirm]' ).forEach( function ( button ) {
		button.addEventListener( 'click', function ( event ) {
			if ( ! window.confirm( cfg.i18n.confirm ) ) {
				event.preventDefault();
			}
		} );
	} );

	var addRecipient = document.getElementById( 'bee-monitor-add-recipient' );
	var recipientRows = document.getElementById( 'bee-monitor-recipient-rows' );
	var recipientTemplate = document.getElementById( 'bee-monitor-recipient-template' );
	if ( addRecipient && recipientRows && recipientTemplate ) {
		addRecipient.addEventListener( 'click', function () {
			var index = 'n' + Date.now();
			var html = recipientTemplate.innerHTML.split( '__INDEX__' ).join( index );
			var holder = document.createElement( 'tbody' );
			holder.innerHTML = html;
			var row = holder.querySelector( 'tr' );
			recipientRows.appendChild( row );
			var email = row.querySelector( 'input[type="email"]' );
			if ( email ) {
				email.focus();
			}
		} );
		recipientRows.addEventListener( 'click', function ( event ) {
			var button = event.target.closest( '.bee-monitor-remove-recipient' );
			if ( button ) {
				var row = button.closest( 'tr' );
				if ( row ) {
					row.parentNode.removeChild( row );
					addRecipient.focus();
				}
			}
		} );
	}

	document.querySelectorAll( '[data-bee-monitor-copy]' ).forEach( function ( button ) {
		button.addEventListener( 'click', function () {
			var target = document.getElementById( button.getAttribute( 'data-bee-monitor-copy' ) );
			var status = button.parentNode.querySelector( '.bee-monitor-copy-status' );
			var label = button.querySelector( '.bee-monitor-btn-label' );
			if ( ! target ) {
				return;
			}
			var text = target.textContent;
			var done = function ( ok ) {
				var message = ok ? cfg.i18n.copied : cfg.i18n.copyFailed;
				if ( status ) {
					status.textContent = message;
				}
				if ( label ) {
					var original = label.getAttribute( 'data-original' ) || label.textContent;
					label.setAttribute( 'data-original', original );
					label.textContent = message;
					window.setTimeout( function () {
						label.textContent = original;
					}, 2000 );
				}
			};
			if ( navigator.clipboard && window.isSecureContext ) {
				navigator.clipboard.writeText( text ).then( function () {
					done( true );
				}, function () {
					done( false );
				} );
				return;
			}
			var range = document.createRange();
			range.selectNodeContents( target );
			var selection = window.getSelection();
			selection.removeAllRanges();
			selection.addRange( range );
			done( false );
		} );
	} );

	var runButton = document.getElementById( 'bee-monitor-run' );
	var fullButton = document.getElementById( 'bee-monitor-run-full' );
	var remoteButton = document.getElementById( 'bee-monitor-run-remote' );
	var activeButton = null;
	var cancelButton = document.getElementById( 'bee-monitor-cancel' );
	var statusBox = document.getElementById( 'bee-monitor-scan-status' );
	var bar = document.getElementById( 'bee-monitor-progress-bar' );
	var progress = document.getElementById( 'bee-monitor-progress' );
	if ( ! runButton || ! progress ) {
		return;
	}
	var stopping = false;

	function setLabel( button, text ) {
		var label = button && button.querySelector( '.bee-monitor-btn-label' );
		if ( label ) {
			label.textContent = text;
		}
	}

	function setRunning( running ) {
		[ runButton, fullButton, remoteButton ].forEach( function ( button ) {
			if ( ! button ) {
				return;
			}
			button.disabled = running;
			button.classList.toggle( 'is-busy', running && button === activeButton );
			button.setAttribute( 'aria-busy', running && button === activeButton ? 'true' : 'false' );
		} );
		if ( cancelButton ) {
			cancelButton.hidden = ! running;
			cancelButton.disabled = false;
		}
		if ( statusBox ) {
			statusBox.hidden = false;
		}
	}

	function setBar( percent ) {
		if ( ! bar ) {
			return;
		}
		if ( percent === null || percent === undefined ) {
			bar.removeAttribute( 'value' );
		} else {
			bar.value = percent;
		}
	}

	function fail( message ) {
		progress.textContent = message;
		progress.className = 'bee-monitor-error';
		setBar( 0 );
		setLabel( runButton, cfg.i18n.resume );
		setRunning( false );
		if ( cancelButton ) {
			cancelButton.hidden = true;
		}
	}

	function post( action, extra ) {
		var body = new FormData();
		body.append( 'action', action );
		body.append( 'nonce', cfg.nonce );
		Object.keys( extra || {} ).forEach( function ( key ) {
			body.append( key, extra[ key ] );
		} );
		return fetch( cfg.ajaxUrl, { method: 'POST', body: body, credentials: 'same-origin' } ).then( function ( response ) {
			if ( response.status === 403 ) {
				throw new Error( 'forbidden' );
			}
			return response.text();
		} ).then( function ( text ) {
			if ( text === '-1' || text === '0' ) {
				throw new Error( 'expired' );
			}
			var json = JSON.parse( text );
			if ( ! json || ! json.success ) {
				throw new Error( 'failed' );
			}
			return json.data;
		} );
	}

	function errorMessage( error ) {
		if ( error && error.message === 'forbidden' ) {
			return cfg.i18n.forbidden;
		}
		if ( error && error.message === 'expired' ) {
			return cfg.i18n.expired;
		}
		return cfg.i18n.error;
	}

	function finish( data ) {
		var stats = data.stats || {};
		setRunning( false );
		if ( cancelButton ) {
			cancelButton.hidden = true;
		}
		if ( data.cancelled ) {
			setBar( 0 );
			progress.className = '';
			progress.textContent = cfg.i18n.cancelled;
			setLabel( runButton, cfg.i18n.resume );
			return;
		}
		setBar( 100 );
		progress.className = 'bee-monitor-success';
		progress.textContent = format( cfg.i18n.done, [ stats.files || 0, stats.findings || 0 ] ) + ' ';
		var link = document.createElement( 'a' );
		link.href = cfg.findingsUrl;
		link.textContent = cfg.i18n.view;
		progress.appendChild( link );
	}

	function step( start, full, remote ) {
		if ( stopping ) {
			return;
		}
		var extra = start ? { start: '1' } : {};
		if ( start && full ) {
			extra.full = '1';
		}
		if ( start && remote ) {
			extra.remote = '1';
		}
		post( 'bee_monitor_scan_step', extra ).then( function ( data ) {
			if ( data.done ) {
				finish( data );
				return;
			}
			var stats = data.stats || {};
			progress.className = '';
			progress.textContent = data.locked ? data.message : format( cfg.i18n.progress, [ data.phase_label || data.phase, stats.files || 0, stats.findings || 0 ] );
			setBar( data.percent );
			window.setTimeout( function () {
				step( false );
			}, data.locked ? 3000 : 250 );
		} ).catch( function ( error ) {
			fail( errorMessage( error ) );
		} );
	}

	function begin( button, full, remote ) {
		stopping = false;
		activeButton = button;
		setRunning( true );
		setBar( null );
		progress.className = '';
		progress.textContent = remote ? cfg.i18n.startingRemote : ( full ? cfg.i18n.startingFull : cfg.i18n.starting );
		step( true, full, remote );
	}

	runButton.addEventListener( 'click', function () {
		begin( runButton, false );
	} );
	if ( remoteButton ) {
		remoteButton.addEventListener( 'click', function () {
			begin( remoteButton, false, true );
		} );
	}
	if ( fullButton ) {
		fullButton.addEventListener( 'click', function () {
			begin( fullButton, true );
		} );
	}

	if ( cancelButton ) {
		cancelButton.addEventListener( 'click', function () {
			stopping = true;
			cancelButton.disabled = true;
			progress.textContent = cfg.i18n.cancelling;
			post( 'bee_monitor_scan_cancel' ).then( function ( data ) {
				finish( { cancelled: true, stats: data.stats } );
			} ).catch( function ( error ) {
				fail( errorMessage( error ) );
			} );
		} );
	}

	if ( runButton.getAttribute( 'data-autostart' ) ) {
		runButton.click();
	}
}() );
