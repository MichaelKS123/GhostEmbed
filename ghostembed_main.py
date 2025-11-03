"""
GhostEmbed: Advanced Steganography Tool
Author: Michael Semera
Description: Hide and retrieve secret messages within image pixels using LSB steganography
with encryption and error detection capabilities
"""

import numpy as np
from PIL import Image
import hashlib
import os
import struct
from typing import Tuple, Optional
import secrets


class GhostEmbedException(Exception):
    """Custom exception for GhostEmbed operations."""
    pass


class BitManipulator:
    """
    Advanced bitwise operations for steganography.
    Handles LSB (Least Significant Bit) manipulation.
    """
    
    @staticmethod
    def set_lsb(byte: int, bit: int) -> int:
        """
        Set the least significant bit of a byte.
        
        Args:
            byte: Original byte value (0-255)
            bit: Bit to set (0 or 1)
            
        Returns:
            Modified byte with LSB set to specified bit
        """
        # Clear LSB and set new bit
        return (byte & 0xFE) | (bit & 0x01)
    
    @staticmethod
    def get_lsb(byte: int) -> int:
        """
        Extract the least significant bit from a byte.
        
        Args:
            byte: Byte to extract from
            
        Returns:
            LSB value (0 or 1)
        """
        return byte & 0x01
    
    @staticmethod
    def set_2lsb(byte: int, bits: int) -> int:
        """
        Set the two least significant bits of a byte.
        
        Args:
            byte: Original byte value
            bits: Two bits to set (0-3)
            
        Returns:
            Modified byte
        """
        return (byte & 0xFC) | (bits & 0x03)
    
    @staticmethod
    def get_2lsb(byte: int) -> int:
        """
        Extract the two least significant bits.
        
        Args:
            byte: Byte to extract from
            
        Returns:
            Two LSB values (0-3)
        """
        return byte & 0x03
    
    @staticmethod
    def bytes_to_bits(data: bytes) -> list:
        """
        Convert bytes to list of individual bits.
        
        Args:
            data: Bytes to convert
            
        Returns:
            List of bits (0s and 1s)
        """
        bits = []
        for byte in data:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        return bits
    
    @staticmethod
    def bits_to_bytes(bits: list) -> bytes:
        """
        Convert list of bits back to bytes.
        
        Args:
            bits: List of bits
            
        Returns:
            Reconstructed bytes
        """
        # Pad to multiple of 8
        while len(bits) % 8 != 0:
            bits.append(0)
        
        byte_array = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            byte_array.append(byte)
        
        return bytes(byte_array)


class XORCipher:
    """
    Simple XOR cipher for message encryption.
    Provides basic security layer for hidden messages.
    """
    
    @staticmethod
    def generate_key(password: str, length: int) -> bytes:
        """
        Generate encryption key from password using SHA-256.
        
        Args:
            password: User password
            length: Desired key length
            
        Returns:
            Encryption key bytes
        """
        # Use SHA-256 to derive key
        key = hashlib.sha256(password.encode()).digest()
        
        # Extend key to required length
        extended_key = bytearray()
        while len(extended_key) < length:
            extended_key.extend(key)
        
        return bytes(extended_key[:length])
    
    @staticmethod
    def encrypt(data: bytes, password: str) -> bytes:
        """
        Encrypt data using XOR cipher.
        
        Args:
            data: Data to encrypt
            password: Encryption password
            
        Returns:
            Encrypted data
        """
        key = XORCipher.generate_key(password, len(data))
        
        encrypted = bytearray()
        for i in range(len(data)):
            encrypted.append(data[i] ^ key[i])
        
        return bytes(encrypted)
    
    @staticmethod
    def decrypt(data: bytes, password: str) -> bytes:
        """
        Decrypt data using XOR cipher.
        XOR is symmetric, so encryption = decryption.
        
        Args:
            data: Encrypted data
            password: Decryption password
            
        Returns:
            Decrypted data
        """
        return XORCipher.encrypt(data, password)


class MessageFormatter:
    """
    Format messages with metadata for robust encoding/decoding.
    Includes length, checksum, and magic bytes.
    """
    
    MAGIC_HEADER = b'GHOST'  # Magic bytes to identify embedded message
    VERSION = 1
    
    @staticmethod
    def create_header(message_length: int, checksum: bytes) -> bytes:
        """
        Create message header with metadata.
        
        Format:
        - Magic bytes (5 bytes): 'GHOST'
        - Version (1 byte): Format version
        - Message length (4 bytes): Length of actual message
        - Checksum (4 bytes): First 4 bytes of SHA-256 hash
        
        Total: 14 bytes
        """
        header = bytearray()
        header.extend(MessageFormatter.MAGIC_HEADER)
        header.append(MessageFormatter.VERSION)
        header.extend(struct.pack('>I', message_length))  # Big-endian 4-byte int
        header.extend(checksum[:4])
        
        return bytes(header)
    
    @staticmethod
    def parse_header(data: bytes) -> Tuple[int, bytes]:
        """
        Parse header to extract metadata.
        
        Returns:
            Tuple of (message_length, checksum)
        """
        if len(data) < 14:
            raise GhostEmbedException("Insufficient data for header")
        
        # Verify magic bytes
        if data[:5] != MessageFormatter.MAGIC_HEADER:
            raise GhostEmbedException("Invalid header: Magic bytes not found")
        
        # Check version
        version = data[5]
        if version != MessageFormatter.VERSION:
            raise GhostEmbedException(f"Unsupported version: {version}")
        
        # Extract message length
        message_length = struct.unpack('>I', data[6:10])[0]
        
        # Extract checksum
        checksum = data[10:14]
        
        return message_length, checksum
    
    @staticmethod
    def calculate_checksum(data: bytes) -> bytes:
        """
        Calculate SHA-256 checksum of data.
        
        Returns:
            First 4 bytes of hash
        """
        hash_obj = hashlib.sha256(data)
        return hash_obj.digest()[:4]
    
    @staticmethod
    def format_message(message: bytes) -> bytes:
        """
        Format message with header for embedding.
        
        Args:
            message: Original message bytes
            
        Returns:
            Formatted message with header
        """
        checksum = MessageFormatter.calculate_checksum(message)
        header = MessageFormatter.create_header(len(message), checksum)
        
        return header + message
    
    @staticmethod
    def verify_message(formatted_message: bytes) -> bytes:
        """
        Verify and extract original message from formatted data.
        
        Args:
            formatted_message: Message with header
            
        Returns:
            Original message if valid
        """
        message_length, stored_checksum = MessageFormatter.parse_header(formatted_message)
        
        # Extract message
        message = formatted_message[14:14 + message_length]
        
        # Verify checksum
        calculated_checksum = MessageFormatter.calculate_checksum(message)
        
        if calculated_checksum != stored_checksum:
            raise GhostEmbedException("Checksum verification failed: Message may be corrupted")
        
        return message


class GhostEmbed:
    """
    Main steganography engine.
    Embeds and extracts messages from images using LSB technique.
    """
    
    def __init__(self, lsb_bits: int = 1):
        """
        Initialize GhostEmbed.
        
        Args:
            lsb_bits: Number of LSBs to use (1 or 2)
        """
        if lsb_bits not in [1, 2]:
            raise ValueError("lsb_bits must be 1 or 2")
        
        self.lsb_bits = lsb_bits
        self.bit_manipulator = BitManipulator()
        self.cipher = XORCipher()
        self.formatter = MessageFormatter()
    
    def calculate_capacity(self, image_path: str) -> int:
        """
        Calculate maximum message capacity for an image.
        
        Args:
            image_path: Path to image file
            
        Returns:
            Maximum message size in bytes
        """
        try:
            img = Image.open(image_path)
            img_array = np.array(img)
            
            # Total pixels × channels × LSB bits / 8 bits per byte
            total_bits = img_array.size * self.lsb_bits
            capacity = total_bits // 8
            
            # Subtract header size
            capacity -= 14  # Header size
            
            return max(0, capacity)
            
        except Exception as e:
            raise GhostEmbedException(f"Error calculating capacity: {str(e)}")
    
    def embed(self, image_path: str, message: str, output_path: str, 
             password: Optional[str] = None) -> dict:
        """
        Embed a secret message into an image.
        
        Args:
            image_path: Path to cover image
            message: Secret message to hide
            output_path: Path for output image
            password: Optional encryption password
            
        Returns:
            Dictionary with embedding statistics
        """
        print(f"📷 Loading image: {image_path}")
        
        try:
            # Load image
            img = Image.open(image_path)
            img_array = np.array(img).copy()
            
            # Convert message to bytes
            message_bytes = message.encode('utf-8')
            
            # Encrypt if password provided
            if password:
                print("🔐 Encrypting message...")
                message_bytes = self.cipher.encrypt(message_bytes, password)
            
            # Format message with header
            formatted_message = self.formatter.format_message(message_bytes)
            
            # Check capacity
            capacity = self.calculate_capacity(image_path)
            if len(formatted_message) > capacity:
                raise GhostEmbedException(
                    f"Message too large: {len(formatted_message)} bytes exceeds "
                    f"capacity of {capacity} bytes"
                )
            
            print(f"💾 Embedding {len(formatted_message)} bytes...")
            
            # Convert message to bits
            message_bits = self.bit_manipulator.bytes_to_bits(formatted_message)
            
            # Embed bits into image
            flat_array = img_array.flatten()
            bit_index = 0
            
            if self.lsb_bits == 1:
                # Use 1 LSB per pixel value
                for i in range(len(message_bits)):
                    if bit_index >= len(flat_array):
                        break
                    flat_array[bit_index] = self.bit_manipulator.set_lsb(
                        flat_array[bit_index], 
                        message_bits[i]
                    )
                    bit_index += 1
            else:
                # Use 2 LSBs per pixel value
                for i in range(0, len(message_bits), 2):
                    if bit_index >= len(flat_array):
                        break
                    
                    if i + 1 < len(message_bits):
                        two_bits = (message_bits[i] << 1) | message_bits[i + 1]
                    else:
                        two_bits = message_bits[i] << 1
                    
                    flat_array[bit_index] = self.bit_manipulator.set_2lsb(
                        flat_array[bit_index],
                        two_bits
                    )
                    bit_index += 1
            
            # Reshape and save
            stego_array = flat_array.reshape(img_array.shape)
            stego_img = Image.fromarray(stego_array.astype('uint8'))
            stego_img.save(output_path)
            
            print(f"✓ Message embedded successfully!")
            print(f"💾 Saved to: {output_path}")
            
            # Calculate statistics
            original_size = os.path.getsize(image_path)
            stego_size = os.path.getsize(output_path)
            
            return {
                'message_length': len(message),
                'bytes_embedded': len(formatted_message),
                'capacity_used': (len(formatted_message) / capacity) * 100,
                'original_size': original_size,
                'stego_size': stego_size,
                'size_change': stego_size - original_size,
                'encrypted': password is not None
            }
            
        except Exception as e:
            raise GhostEmbedException(f"Embedding failed: {str(e)}")
    
    def extract(self, stego_image_path: str, 
               password: Optional[str] = None) -> str:
        """
        Extract hidden message from a stego image.
        
        Args:
            stego_image_path: Path to image with hidden message
            password: Decryption password if message was encrypted
            
        Returns:
            Extracted message as string
        """
        print(f"📷 Loading stego image: {stego_image_path}")
        
        try:
            # Load image
            img = Image.open(stego_image_path)
            img_array = np.array(img)
            
            print("🔍 Extracting hidden data...")
            
            # Extract bits
            flat_array = img_array.flatten()
            extracted_bits = []
            
            if self.lsb_bits == 1:
                # Extract 1 LSB per pixel value
                # Extract enough for header first
                for i in range(14 * 8):  # 14 bytes for header
                    if i >= len(flat_array):
                        break
                    bit = self.bit_manipulator.get_lsb(flat_array[i])
                    extracted_bits.append(bit)
            else:
                # Extract 2 LSBs per pixel value
                for i in range((14 * 8) // 2 + 1):
                    if i >= len(flat_array):
                        break
                    two_bits = self.bit_manipulator.get_2lsb(flat_array[i])
                    extracted_bits.append((two_bits >> 1) & 1)
                    extracted_bits.append(two_bits & 1)
            
            # Convert to bytes and parse header
            header_bytes = self.bit_manipulator.bits_to_bytes(extracted_bits[:14 * 8])
            message_length, checksum = self.formatter.parse_header(header_bytes)
            
            print(f"📊 Message length: {message_length} bytes")
            
            # Extract remaining message bits
            total_bits_needed = (14 + message_length) * 8
            
            if self.lsb_bits == 1:
                while len(extracted_bits) < total_bits_needed:
                    idx = len(extracted_bits)
                    if idx >= len(flat_array):
                        break
                    bit = self.bit_manipulator.get_lsb(flat_array[idx])
                    extracted_bits.append(bit)
            else:
                while len(extracted_bits) < total_bits_needed:
                    idx = len(extracted_bits) // 2
                    if idx >= len(flat_array):
                        break
                    two_bits = self.bit_manipulator.get_2lsb(flat_array[idx])
                    extracted_bits.append((two_bits >> 1) & 1)
                    extracted_bits.append(two_bits & 1)
            
            # Convert all extracted bits to bytes
            formatted_message = self.bit_manipulator.bits_to_bytes(
                extracted_bits[:total_bits_needed]
            )
            
            # Verify and extract message
            print("✓ Verifying message integrity...")
            message_bytes = self.formatter.verify_message(formatted_message)
            
            # Decrypt if password provided
            if password:
                print("🔓 Decrypting message...")
                message_bytes = self.cipher.decrypt(message_bytes, password)
            
            # Convert to string
            message = message_bytes.decode('utf-8')
            
            print("✓ Message extracted successfully!")
            
            return message
            
        except GhostEmbedException as e:
            raise e
        except Exception as e:
            raise GhostEmbedException(f"Extraction failed: {str(e)}")
    
    def analyze_image(self, image_path: str) -> dict:
        """
        Analyze an image for steganography detection.
        
        Args:
            image_path: Path to image
            
        Returns:
            Dictionary with analysis results
        """
        try:
            img = Image.open(image_path)
            img_array = np.array(img)
            
            # Check for embedded message
            has_message = False
            try:
                flat_array = img_array.flatten()
                extracted_bits = []
                
                # Try to extract header
                for i in range(14 * 8):
                    if i >= len(flat_array):
                        break
                    bit = self.bit_manipulator.get_lsb(flat_array[i])
                    extracted_bits.append(bit)
                
                header_bytes = self.bit_manipulator.bits_to_bytes(extracted_bits)
                
                # Check for magic bytes
                if header_bytes[:5] == self.formatter.MAGIC_HEADER:
                    has_message = True
                    message_length, _ = self.formatter.parse_header(header_bytes)
                else:
                    message_length = 0
                    
            except:
                has_message = False
                message_length = 0
            
            return {
                'width': img.width,
                'height': img.height,
                'channels': len(img.getbands()),
                'mode': img.mode,
                'capacity_bytes': self.calculate_capacity(image_path),
                'has_ghostembed_message': has_message,
                'detected_message_length': message_length if has_message else None
            }
            
        except Exception as e:
            raise GhostEmbedException(f"Analysis failed: {str(e)}")


def main():
    """
    Command-line interface for GhostEmbed.
    """
    import argparse
    
    print("\n" + "="*60)
    print(" "*18 + "👻 GHOSTEMBED 👻")
    print(" "*12 + "Advanced Steganography Tool")
    print(" "*18 + "by Michael Semera")
    print("="*60 + "\n")
    
    parser = argparse.ArgumentParser(
        description='GhostEmbed: Hide and extract secret messages in images',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Embed a message
  python ghostembed.py embed cover.png "Secret message" output.png
  
  # Embed with encryption
  python ghostembed.py embed cover.png "Secret" output.png -p mypassword
  
  # Extract a message
  python ghostembed.py extract stego.png
  
  # Extract with decryption
  python ghostembed.py extract stego.png -p mypassword
  
  # Check image capacity
  python ghostembed.py capacity cover.png
  
  # Analyze image
  python ghostembed.py analyze image.png
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Embed command
    embed_parser = subparsers.add_parser('embed', help='Embed message in image')
    embed_parser.add_argument('image', help='Cover image path')
    embed_parser.add_argument('message', help='Secret message to hide')
    embed_parser.add_argument('output', help='Output stego image path')
    embed_parser.add_argument('-p', '--password', help='Encryption password')
    embed_parser.add_argument('-l', '--lsb', type=int, choices=[1, 2], default=1,
                             help='Number of LSB bits to use (default: 1)')
    
    # Extract command
    extract_parser = subparsers.add_parser('extract', help='Extract message from image')
    extract_parser.add_argument('image', help='Stego image path')
    extract_parser.add_argument('-p', '--password', help='Decryption password')
    extract_parser.add_argument('-l', '--lsb', type=int, choices=[1, 2], default=1,
                               help='Number of LSB bits used (default: 1)')
    
    # Capacity command
    capacity_parser = subparsers.add_parser('capacity', help='Check image capacity')
    capacity_parser.add_argument('image', help='Image path')
    capacity_parser.add_argument('-l', '--lsb', type=int, choices=[1, 2], default=1,
                                help='Number of LSB bits (default: 1)')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze image')
    analyze_parser.add_argument('image', help='Image path')
    analyze_parser.add_argument('-l', '--lsb', type=int, choices=[1, 2], default=1,
                               help='Number of LSB bits (default: 1)')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        if args.command == 'embed':
            ghost = GhostEmbed(lsb_bits=args.lsb)
            stats = ghost.embed(args.image, args.message, args.output, args.password)
            
            print(f"\n{'='*60}")
            print("EMBEDDING STATISTICS")
            print(f"{'='*60}")
            print(f"Message length: {stats['message_length']} characters")
            print(f"Bytes embedded: {stats['bytes_embedded']} bytes")
            print(f"Capacity used: {stats['capacity_used']:.2f}%")
            print(f"Encrypted: {'Yes' if stats['encrypted'] else 'No'}")
            print(f"{'='*60}\n")
            
        elif args.command == 'extract':
            ghost = GhostEmbed(lsb_bits=args.lsb)
            message = ghost.extract(args.image, args.password)
            
            print(f"\n{'='*60}")
            print("EXTRACTED MESSAGE")
            print(f"{'='*60}")
            print(message)
            print(f"{'='*60}\n")
            
        elif args.command == 'capacity':
            ghost = GhostEmbed(lsb_bits=args.lsb)
            capacity = ghost.calculate_capacity(args.image)
            
            print(f"\n{'='*60}")
            print("IMAGE CAPACITY")
            print(f"{'='*60}")
            print(f"Maximum message size: {capacity:,} bytes")
            print(f"Maximum characters: {capacity:,}")
            print(f"Using {args.lsb} LSB bit(s)")
            print(f"{'='*60}\n")
            
        elif args.command == 'analyze':
            ghost = GhostEmbed(lsb_bits=args.lsb)
            analysis = ghost.analyze_image(args.image)
            
            print(f"\n{'='*60}")
            print("IMAGE ANALYSIS")
            print(f"{'='*60}")
            print(f"Dimensions: {analysis['width']}x{analysis['height']}")
            print(f"Color mode: {analysis['mode']}")
            print(f"Channels: {analysis['channels']}")
            print(f"Capacity: {analysis['capacity_bytes']:,} bytes")
            print(f"GhostEmbed message detected: {analysis['has_ghostembed_message']}")
            if analysis['detected_message_length']:
                print(f"Message length: {analysis['detected_message_length']} bytes")
            print(f"{'='*60}\n")
            
    except GhostEmbedException as e:
        print(f"\n❌ Error: {str(e)}\n")
    except KeyboardInterrupt:
        print("\n\n👋 Operation cancelled by user\n")
    except Exception as e:
        print(f"\n❌ Unexpected error: {str(e)}\n")


if __name__ == "__main__":
    main()
