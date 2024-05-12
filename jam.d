import std.ascii;
import std.conv;
import std.algorithm;
import std.utf;
import std.random;
import std.array;
import std.base64;
import std.string;
import std.range;
import std.regex;
import std.stdio;

// -- FUNCTIONS

ubyte[] GetRandomByteArray(
    string text,
    long random_byte_count
    )
{
    long
        random_byte_index;
    uint
        character_index,
        high_seed,
        low_seed,
        random_seed;
    ubyte[]
        random_byte_array;

    random_byte_array = new ubyte[ random_byte_count ];

    low_seed = 0;
    high_seed = 0;

    foreach ( character; text )
    {
        low_seed = ( ( low_seed << 5 ) - low_seed ) + character;
        high_seed = ( ( high_seed << 5 ) - high_seed ) + ( low_seed >>> 31 );

        low_seed &= 0xFFFFFFFF;
        high_seed &= 0xFFFFFFFF;
    }

    for ( random_byte_index = 0;
          random_byte_index < random_byte_count;
          ++random_byte_index )
    {
        low_seed = ( low_seed * 1664525 + 1013904223 ) & 0xFFFFFFFF;
        high_seed = ( high_seed * 1664525 + 1013904223 + ( low_seed >>> 31 ) ) & 0xFFFFFFFF;
        random_seed = ( low_seed ^ high_seed );

        random_byte_array[ random_byte_index ] = cast( ubyte )( random_seed & 0xFF ^ ( random_seed >> 3 ) );
    }

    return random_byte_array;
}

// ~~

ubyte[] GetByteArrayFromText(
    string text
    )
{
    return text.representation.dup();
}

// ~~

string GetTextFromByteArray(
    ubyte[] byte_array
    )
{
    return cast( string )byte_array;
}

// ~~

string GetBinaryTextFromByteArray(
    ubyte[] byte_array
    )
{
    return Base64.encode( byte_array );
}

// ~~

ubyte[] GetByteArrayFromBinaryText(
    string binary_text
    )
{
    return Base64.decode( binary_text );
}

// ~~

uint GetNaturalAtByteIndex(
    ubyte[] byte_array,
    long byte_index
    )
{
    return
        ( byte_array[ byte_index ]
          | byte_array[ byte_index + 1 ] << 8
          | byte_array[ byte_index + 2 ] << 16
          | byte_array[ byte_index + 3 ] << 24 ) >>> 0;
}

// ~~

uint GetRotatedNatural(
    uint natural,
    int bit_count
    )
{
    return ( natural << bit_count ) | ( natural >>> ( 32 - bit_count ) );
}

// ~~

void QuarterRound(
    uint[] natural_array,
    long first_natural_index,
    long second_natural_index,
    long third_natural_index,
    long fourth_natural_index
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

ubyte[] GetEncryptedByteArray(
    ubyte[] byte_array,
    ubyte[] key_byte_array,
    ubyte[] nonce_byte_array
    )
{
    long
        buffer_byte_index,
        byte_index,
        natural_index,
        update_index;
    ubyte[]
        buffer_byte_array,
        encrypted_byte_array;
    uint
        natural;
    uint[]
        state_natural_array,
        working_state_natural_array;

    state_natural_array = new uint[ 16 ];
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

    buffer_byte_array = new ubyte[ 64 ];
    buffer_byte_index = 64;

    encrypted_byte_array = new ubyte[]( byte_array.length );

    for ( byte_index = 0;
          byte_index < byte_array.length;
          ++byte_index )
    {
        if ( buffer_byte_index >= 64 )
        {
            working_state_natural_array = state_natural_array.dup;

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

                buffer_byte_array[ natural_index * 4 ] = cast( ubyte )( natural & 0xff );
                buffer_byte_array[ natural_index * 4 + 1 ] = cast( ubyte )( ( natural >> 8 ) & 0xff );
                buffer_byte_array[ natural_index * 4 + 2 ] = cast( ubyte )( ( natural >> 16 ) & 0xff );
                buffer_byte_array[ natural_index * 4 + 3 ] = cast( ubyte )( ( natural >> 24 ) & 0xff );
            }

            state_natural_array[ 12 ]++;
            buffer_byte_index = 0;
        }

        encrypted_byte_array[ byte_index ] = byte_array[ byte_index ] ^ buffer_byte_array[ buffer_byte_index++ ];
    }

    return encrypted_byte_array;
}

// ~~

string GetEncryptedText(
    string text,
    string key,
    string nonce
    )
{
    ubyte[]
        decrypted_byte_array,
        encrypted_byte_array,
        key_byte_array,
        nonce_byte_array;

    key_byte_array = GetRandomByteArray( key, 32 );
    nonce_byte_array = GetRandomByteArray( nonce, 12 );

    auto ReplaceMatch(
        Captures!string captures
        )
    {
        auto decrypted_byte_array = GetByteArrayFromText( captures[ 1 ] );
        auto encrypted_byte_array = GetEncryptedByteArray( decrypted_byte_array, key_byte_array, nonce_byte_array );

        return "🔒[" ~ GetBinaryTextFromByteArray( encrypted_byte_array ) ~ "]🔒";
    }

    return text.replaceAll!ReplaceMatch( regex( `🔓\[(.*?)\]🔓` ) );
}

// ~~

string GetDecryptedText(
    string text,
    string key,
    string nonce
    )
{
    ubyte[]
        decrypted_byte_array,
        encrypted_byte_array,
        key_byte_array,
        nonce_byte_array;

    key_byte_array = GetRandomByteArray( key, 32 );
    nonce_byte_array = GetRandomByteArray( nonce, 12 );

    auto ReplaceMatch(
        Captures!string captures
        )
    {
        auto encrypted_byte_array = GetByteArrayFromBinaryText( captures[ 1 ] );
        auto decrypted_byte_array = GetEncryptedByteArray( encrypted_byte_array, key_byte_array, nonce_byte_array );

        return "🔓[" ~ GetTextFromByteArray( decrypted_byte_array ) ~ "]🔓";
    }

    return text.replaceAll!ReplaceMatch( regex( `🔒\[(.*?)\]🔒` ) );
}

// ~~

void Test(
    )
{
    string
        key,
        nonce,
        text;

    key = "the-key";
    nonce = "the-nonce";

    text = "Type your text with tags like 🔓[Encrypt this]🔓 and 🔒[6iHRVmBA6iM0rprF]🔒";

    writeln( text );

    text = GetEncryptedText( text, key, nonce );
    writeln( text );

    text = GetDecryptedText( text, key, nonce );
    writeln( text );

    text = GetEncryptedText( text, key, nonce );
    writeln( text );
}

// ~~

void main(
    )
{
    Test();
}
