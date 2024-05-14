import core.stdc.stdlib : exit;
//import std.algorithm;
//import std.array;
//import std.ascii;
import std.base64 : Base64;
import std.conv : to;
import std.file : dirEntries, readText, write, SpanMode;
//import std.range;
import std.regex : regex, replaceAll, Captures;
import std.stdio : writeln;
import std.string : endsWith, replace, representation, startsWith;
//import std.utf;

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

        return "🔒 " ~ GetBinaryTextFromByteArray( encrypted_byte_array ) ~ " 🔒";
    }

    return text.replaceAll!ReplaceMatch( regex( `🔓 ([^🔓]*?) 🔓` ) );
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

        return "🔓 " ~ GetTextFromByteArray( decrypted_byte_array ) ~ " 🔓";
    }

    return text.replaceAll!ReplaceMatch( regex( `🔒 ([^🔒]*?) 🔒` ) );
}

// ~~

void PrintError(
    string message
    )
{
    writeln( "*** ERROR : ", message );
}

// ~~

void Abort(
    string message
    )
{
    PrintError( message );

    exit( -1 );
}

// ~~

void Abort(
    string message,
    Exception exception
    )
{
    PrintError( message );
    PrintError( exception.msg );

    exit( -1 );
}

// ~~

string GetPhysicalPath(
    string path
    )
{
    return path.replace( '/', '\\' );
}

// ~~

string GetLogicalPath(
    string path
    )
{
    return path.replace( '\\', '/' );
}

// ~~

string ReadText(
    string file_path
    )
{
    string
        file_text;

    writeln( "Reading file : ", file_path );

    try
    {
        file_text = file_path.GetPhysicalPath().readText();
    }
    catch ( Exception exception )
    {
        Abort( "Can't read file : " ~ file_path, exception );
    }

    return file_text;
}

// ~~

void WriteText(
    string file_path,
    string file_text
    )
{
    writeln( "Writing file : ", file_path );

    try
    {
        file_path.GetPhysicalPath().write( file_text );
    }
    catch ( Exception exception )
    {
        Abort( "Can't write file : " ~ file_path, exception );
    }
}

// ~~

void ProcessFile(
    string file_path,
    string key,
    string nonce,
    bool file_is_encrypted
    )
{
    if ( file_is_encrypted )
    {
        file_path.WriteText(
            file_path.ReadText().GetEncryptedText( key, nonce )
            );
    }
    else
    {
        file_path.WriteText(
            file_path.ReadText().GetDecryptedText( key, nonce )
            );
    }
}

// ~~

void ProcessFolder(
    string folder_path,
    string[] filter_array,
    string key,
    string nonce,
    bool file_is_encrypted
    )
{
    writeln(
        file_is_encrypted ? "Encrypting folder : " : "Decrypting folder : ",
        folder_path
        );

    try
    {
        foreach ( filter; filter_array )
        {
            writeln(
                file_is_encrypted ? "Encrypting files : " : "Decrypting files : ",
                filter
                );

            foreach ( folder_entry; dirEntries( folder_path, filter, SpanMode.depth ) )
            {
                if ( folder_entry.isFile )
                {
                    ProcessFile( folder_entry.name.GetLogicalPath(), key, nonce, file_is_encrypted );
                }
            }
        }
    }
    catch ( Exception exception )
    {
        Abort( "Can't process files", exception );
    }
}

// ~~

void main(
    string[] argument_array
    )
{
    string
        option;

    argument_array = argument_array[ 1 .. $ ];

    while ( argument_array.length >= 1
            && argument_array[ 0 ].startsWith( "--" ) )
    {
        option = argument_array[ 0 ];
        argument_array = argument_array[ 1 .. $ ];

        if ( ( option == "--encrypt"
               || option == "--decrypt" )
             && argument_array.length >= 4
             && argument_array[ 2 ].GetLogicalPath().endsWith( '/' ) )
        {
            ProcessFolder(
                argument_array[ 2 ].GetLogicalPath(),
                argument_array[ 3 .. $ ],
                argument_array[ 0 ],
                argument_array[ 1 ],
                ( option == "--encrypt" )
                );

            argument_array = null;
        }
        else
        {
            break;
        }
    }

    if ( argument_array.length != 0 )
    {
        writeln( "Usage :" );
        writeln( "    jam <option>" );
        writeln( "Options :" );
        writeln( "    --encrypt <key> <nonce> <folder path> <filter> [<filter> ...]" );
        writeln( "    --decrypt <key> <nonce> <folder path> <filter> [<filter> ...]" );
        writeln( "Examples :" );
        writeln( "    jam --encrypt the-key the-nonce FOLDER/ *.txt" );
        writeln( "    jam --decrypt the-key the-nonce FOLDER/ *.txt" );

        Abort( "Invalid arguments : " ~ argument_array.to!string() );
    }
}
