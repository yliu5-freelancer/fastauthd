#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <qrencode.h>
#include <openssl/rand.h>
#include <cairo.h>
#include <curl/curl.h>

// Function to URL-encode a string
char* url_encode(const char* str) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        return NULL;  // Return NULL if curl_easy_init fails
    }

    // Estimate the length of the output string
    int out_length = curl_easy_escape(curl, str, 0);
    if (out_length == 0) {
        curl_easy_cleanup(curl);
        return NULL;
    }

    // Allocate memory for the encoded string
    char* encoded = malloc(out_length + 1);
    if (encoded == NULL) {
        curl_easy_cleanup(curl);
        return NULL;
    }

    // Perform the URL encoding
    curl_easy_escape(curl, str, 0);  // Perform encoding
    curl_easy_cleanup(curl);
    return encoded;
}

void generate_base32_secret(char *output, size_t length) {
    unsigned char secret[length];
    
    // Generate random bytes
    if (RAND_bytes(secret, length) != 1) {
        fprintf(stderr, "Error generating random bytes\n");
        exit(1);
    }

    // Base32 encode the random bytes
    const char *base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    size_t output_index = 0;
    for (size_t i = 0; i < length; i += 5) {
        unsigned int buffer = 0;
        for (size_t j = 0; j < 5 && (i + j) < length; ++j) {
            buffer = (buffer << 8) | secret[i + j];
        }

        // Encode into base32
        for (size_t j = 0; j < 8 && output_index < length; ++j) {
            output[output_index++] = base32_chars[(buffer >> (3 - j) * 5) & 0x1F];
        }
    }
    output[output_index] = '\0';  // Null terminate the string
}

void generate_otp_url(const char *tenant, const char *user, const char *secret, char *url) {
      snprintf(url, 1024, "otpauth://totp/%s%s?secret=%s&issuer=%s", tenant, user, secret, tenant);

}

void generate_qr_code(const char *url) {
    QRcode *qr;
    unsigned char *output;
    int width, height, x, y;

    // Generate the QR code from the OTP URL
    qr = QRcode_encodeString(url, 0, QR_ECLEVEL_L, QR_MODE_8, 1);
    if (qr == NULL) {
        fprintf(stderr, "Error generating QR code\n");
        return;
    }

    width = qr->width;
    height = qr->width;
    output = qr->data;

    // Print the QR code as text (ASCII art)
    printf("\nQR Code for 2FA:\n");
    for (y = 0; y < height; y++) {
        for (x = 0; x < width; x++) {
            if (output[y * width + x] & 0x01)
                printf("  #  ");
            else
                printf("     ");
        }
        printf("\n");
    }

    // Save the QR code as a PNG file
    cairo_surface_t *surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, width, height);
    cairo_t *cr = cairo_create(surface);
    cairo_set_source_rgb(cr, 1, 1, 1);  // white background
    cairo_paint(cr);
    cairo_set_source_rgb(cr, 0, 0, 0);  // black QR code

    for (y = 0; y < height; y++) {
        for (x = 0; x < width; x++) {
            if (output[y * width + x] & 0x01) {
                cairo_rectangle(cr, x, y, 1, 1);
                cairo_fill(cr);
            }
        }
    }

    // Save QR code to file
    cairo_surface_write_to_png(surface, "azure_mfa_qr_code.png");

    // Clean up
    cairo_destroy(cr);
    cairo_surface_destroy(surface);
    QRcode_free(qr);
}

int main() {
    char secret[16] = {0};  // 16 bytes of secret (base32 encoded later)
    char otp_url[1024] = {0};
    char tenant[256] = {0}, user[256] = {0};

    // Get user input for tenant and user
    printf("Enter tenant (e.g., contoso.com): ");
    fgets(tenant, sizeof(tenant), stdin);
    tenant[strcspn(tenant, "\n")] = 0;  // Remove newline

    printf("Enter user (e.g., user@contoso.com): ");
    fgets(user, sizeof(user), stdin);
    user[strcspn(user, "\n")] = 0;  // Remove newline

    // Generate the base32 secret
    generate_base32_secret(secret, sizeof(secret));

    // Generate the OTP URL for the 2FA QR code
    generate_otp_url(tenant, user, secret, otp_url);

    // Generate the QR code for the OTP URL
    generate_qr_code(otp_url);

    printf("QR code for Azure AD MFA generated and saved as 'azure_mfa_qr_code.png'.\n");
    printf("Use this QR code to scan with your Microsoft Authenticator app.\n");
    printf("Secret: %s\n", secret);

    return 0;
}