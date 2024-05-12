// -- FUNCTIONS

function GetRandomByteArray(
    text,
    random_byte_count
    )
{
    var
        character_index,
        high_seed,
        low_seed,
        random_byte_array,
        random_seed;

    low_seed = 0;
    high_seed = 0;

    for ( character_index = 0;
          character_index < text.length;
          ++character_index )
    {
        low_seed = ( ( low_seed << 5 ) - low_seed ) + text.charCodeAt( character_index );
        high_seed = ( ( high_seed << 5 ) - high_seed ) + ( low_seed >>> 31 );

        low_seed = low_seed & 0xFFFFFFFF;
        high_seed = high_seed & 0xFFFFFFFF;
    }

    random_byte_array = new Uint8Array( random_byte_count );

    for ( random_byte_index = 0;
          random_byte_index < random_byte_count;
          ++random_byte_index )
    {
        low_seed = ( low_seed * 1664525 + 1013904223 ) & 0xFFFFFFFF;
        high_seed = ( high_seed * 1664525 + 1013904223 + ( low_seed >>> 31 ) ) & 0xFFFFFFFF;
        random_seed = ( low_seed ^ high_seed );

        random_byte_array[ random_byte_index ] = random_seed & 0xFF ^ ( random_seed >> 3 );
    }

    return random_byte_array;
}

// ~~

function GetByteArrayFromText(
    text
    )
{
    return new TextEncoder().encode( text );
}

// ~~

function GetTextFromByteArray(
    byte_array
    )
{
    return new TextDecoder().decode( byte_array );
}

// ~~

function GetBinaryTextFromByteArray(
    byte_array
    )
{
    return btoa( String.fromCharCode.apply( null, byte_array ) );
}

// ~~

function GetByteArrayFromBinaryText(
    binary_text
    )
{
    return new Uint8Array( atob( binary_text ).split( '' ).map( character => character.charCodeAt( 0 ) ) );
}

// ~~

function GetNaturalAtByteIndex(
    byte_array,
    byte_index
    )
{
    return (
        byte_array[ byte_index ]
        | byte_array[ byte_index + 1 ] << 8
        | byte_array[ byte_index + 2 ] << 16
        | byte_array[ byte_index + 3 ] << 24
        ) >>> 0;
}

// ~~

function GetRotatedNatural(
    natural,
    bit_count
    )
{
    return ( natural << bit_count ) | ( natural >>> ( 32 - bit_count ) );
}

// ~~

function QuarterRound(
    natural_array,
    first_natural_index,
    second_natural_index,
    third_natural_index,
    fourth_natural_index
    )
{
    natural_array[ first_natural_index ] += natural_array[ second_natural_index ];
    natural_array[ fourth_natural_index ] = GetRotatedNatural( natural_array[ fourth_natural_index ] ^ natural_array[ first_natural_index ], 16 );

    natural_array[ third_natural_index ] += natural_array[ fourth_natural_index ];
    natural_array[ second_natural_index ] = GetRotatedNatural( natural_array[ second_natural_index ] ^ natural_array[ third_natural_index ], 12 );

    natural_array[ first_natural_index ] += natural_array[ second_natural_index ];
    natural_array[ fourth_natural_index ] = GetRotatedNatural( natural_array[ fourth_natural_index ] ^ natural_array[ first_natural_index ], 8 );

    natural_array[ third_natural_index ] += natural_array[ fourth_natural_index ];
    natural_array[ second_natural_index ] = GetRotatedNatural( natural_array[ second_natural_index ] ^ natural_array[ third_natural_index ], 7 );
}

// ~~

function GetEncryptedByteArray(
    byte_array,
    key_byte_array,
    nonce_byte_array
    )
{
    var
        byte_index,
        encrypted_byte_array;
    var
        natural,
        working_state_natural_array,
        natural_index,
        update_index;

    state_natural_array = new Uint32Array( 16 );
    state_natural_array[ 0 ] = 0x61707865;
    state_natural_array[ 1 ] = 0x3320646e;
    state_natural_array[ 2 ] = 0x79622d32;
    state_natural_array[ 3 ] = 0x6b206574;

    for ( natural_index = 0;
          natural_index < 8;
          ++natural_index )
    {
        state_natural_array[ 4 + natural_index ] = GetNaturalAtByteIndex( key_byte_array, natural_index * 4 );
    }

    state_natural_array[ 12 ] = 0;
    state_natural_array[ 13 ] = GetNaturalAtByteIndex( nonce_byte_array, 0 );
    state_natural_array[ 14 ] = GetNaturalAtByteIndex( nonce_byte_array, 4 );
    state_natural_array[ 15 ] = GetNaturalAtByteIndex( nonce_byte_array, 8 );

    buffer_byte_array = new Uint8Array( 64 );
    buffer_byte_index = 64;

    encrypted_byte_array = new Uint8Array( byte_array.length );

    for ( byte_index = 0;
          byte_index < byte_array.length;
          ++byte_index )
    {
        if ( buffer_byte_index >= 64 )
        {
            working_state_natural_array = Uint32Array.from( state_natural_array );

            for ( update_index = 0;
                  update_index < 10;
                  ++update_index )
            {
                QuarterRound( working_state_natural_array, 0, 4, 8, 12 );
                QuarterRound( working_state_natural_array, 1, 5, 9, 13 );
                QuarterRound( working_state_natural_array, 2, 6, 10, 14 );
                QuarterRound( working_state_natural_array, 3, 7, 11, 15 );

                QuarterRound( working_state_natural_array, 0, 5, 10, 15 );
                QuarterRound( working_state_natural_array, 1, 6, 11, 12 );
                QuarterRound( working_state_natural_array, 2, 7, 8, 13 );
                QuarterRound( working_state_natural_array, 3, 4, 9, 14 );
            }

            for ( natural_index = 0;
                  natural_index < 16;
                  ++natural_index )
            {
                working_state_natural_array[ natural_index ] += state_natural_array[ natural_index ];
            }

            for ( natural_index = 0;
                  natural_index < 16;
                  ++natural_index )
            {
                natural = working_state_natural_array[ natural_index ];

                buffer_byte_array[ natural_index * 4 ] = natural & 0xff;
                buffer_byte_array[ natural_index * 4 + 1 ] = ( natural >> 8 ) & 0xff;
                buffer_byte_array[ natural_index * 4 + 2 ] = ( natural >> 16 ) & 0xff;
                buffer_byte_array[ natural_index * 4 + 3 ] = ( natural >> 24 ) & 0xff;
            }

            state_natural_array[ 12 ]++;
            buffer_byte_index = 0;
        }

        encrypted_byte_array[ byte_index ] = byte_array[ byte_index ] ^ buffer_byte_array[ buffer_byte_index++ ];
    }

    return encrypted_byte_array;
}

// ~~

function GetEncryptedText(
    text,
    key,
    nonce
    )
{
    var
        key_byte_array,
        nonce_byte_array;

    key_byte_array = GetRandomByteArray( key, 32 );
    nonce_byte_array = GetRandomByteArray( nonce, 12 );

    return (
        text.replace(
            /🔓\[(.*?)\]🔓/g,
            ( match, decrypted_text ) =>
            {
                let decrypted_byte_array = GetByteArrayFromText( decrypted_text );
                let encrypted_byte_array = GetEncryptedByteArray( decrypted_byte_array, key_byte_array, nonce_byte_array );

                return "🔒[" + GetBinaryTextFromByteArray( encrypted_byte_array ) + "]🔒";
            }
            )
        );
}

// ~~

function GetDecryptedText(
    text,
    key,
    nonce
    )
{
    var
        key_byte_array,
        nonce_byte_array;

    key_byte_array = GetRandomByteArray( key, 32 );
    nonce_byte_array = GetRandomByteArray( nonce, 12 );

    return (
        text.replace(
            /🔒\[(.*?)\]🔒/g,
            ( match, encrypted_text ) =>
            {
                let encrypted_byte_array = GetByteArrayFromBinaryText( encrypted_text );
                let decrypted_byte_array = GetEncryptedByteArray( encrypted_byte_array, key_byte_array, nonce_byte_array );

                return "🔓[" + GetTextFromByteArray( decrypted_byte_array ) + "]🔓";
            }
            )
        );
}
