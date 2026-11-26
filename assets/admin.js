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

	var runButton = document.getElementById( 'bee-monitor-run' );
	var progress = document.getElementById( 'bee-monitor-progress' );
	if ( ! runButton || ! progress ) {
		return;
	}

	function step( start ) {
		var body = new FormData();
		body.append( 'action', 'bee_monitor_scan_step' );
		body.append( 'nonce', cfg.nonce );
		if ( start ) {
			body.append( 'start', '1' );
		}
		fetch( cfg.ajaxUrl, { method: 'POST', body: body, credentials: 'same-origin' } )
			.then( function ( response ) {
				return response.json();
			} )
			.then( function ( json ) {
				if ( ! json || ! json.success ) {
					throw new Error( 'failed' );
				}
				var data = json.data;
				var stats = data.stats || {};
				if ( data.done ) {
					progress.textContent = format( cfg.i18n.done, [ stats.files || 0, stats.findings || 0 ] ) + ' ';
					var link = document.createElement( 'a' );
					link.href = cfg.findingsUrl;
					link.textContent = cfg.i18n.view;
					progress.appendChild( link );
					runButton.disabled = false;
					return;
				}
				progress.textContent = data.locked ? data.message : format( cfg.i18n.running, [ data.phase, stats.files || 0, stats.findings || 0 ] );
				window.setTimeout( function () {
					step( false );
				}, data.locked ? 3000 : 300 );
			} )
			.catch( function () {
				progress.textContent = cfg.i18n.error;
				runButton.disabled = false;
			} );
	}

	runButton.addEventListener( 'click', function () {
		runButton.disabled = true;
		progress.textContent = cfg.i18n.starting;
		step( true );
	} );

	if ( runButton.getAttribute( 'data-autostart' ) ) {
		runButton.click();
	}
}() );
