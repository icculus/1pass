#include <linux/input.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "pkcs5_pbkdf2.h"
#include "aes.h"
#include "base64.h"
#include "md5.h"
#include "keyhook.h"
#include <gtk/gtk.h>

#define STATICARRAYLEN(x) ( (sizeof ((x))) / (sizeof ((x)[0])) )

// plug in a Griffin Powermate, make sure you have access to it, and run with
//  --powermate=/dev/input/eventX
static int powermate_fd = -1;
static int pumpPowermate(void)
{
    struct input_event buf[32];
    int pressed = 0;
    ssize_t br;

    if (powermate_fd == -1)
        return 0;  // nothing to do.

    while ((br = read(powermate_fd, buf, sizeof (buf))) > 0)
    {
        ssize_t i;
        br /= sizeof (buf[0]);
        for (i = 0; i < br; i++)
        {
            struct input_event *ev = &buf[i];
            if ((ev->type == EV_KEY) && (ev->code == BTN_0) && (ev->value))
                pressed = 1;
        } // for
    } // while

    return pressed;
}

static void setPowermateLED(const int enable)
{
    struct input_event ev;
    const int brightness = enable ? 255 : 0;
    const int pulse_speed = 255;
    const int pulse_table = 0;
    const int pulse_awake = enable ? 1 : 0;
    const int pulse_asleep = 0;

    if (powermate_fd == -1)
        return;

    memset(&ev, '\0', sizeof (ev));
    ev.type = EV_MSC;
    ev.code = MSC_PULSELED;
    ev.value = brightness | (pulse_speed << 8) | (pulse_table << 17) | (pulse_asleep << 19) | (pulse_awake << 20);

    if (write(powermate_fd, &ev, sizeof (ev)) != sizeof (ev))
        fprintf(stderr, "WARNING: tried to set Powermate LED and failed: %s\n", strerror(errno));
} // setPowermateLED


static int openPowermate(const char *fname)
{
    static const char const *known_names[] = {
        "Griffin PowerMate", "Griffin SoundKnob"
    };

    char buf[255];
    int ok = 0;
    int fd;
    int i;

    if (!fname)
        return -1;

    if ((fd = open(fname, O_RDWR)) == -1)
        fprintf(stderr, "WARNING: couldn't open Powermate at %s: %s\n", fname, strerror(errno));

    if (ioctl(fd, EVIOCGNAME(sizeof (buf)), buf) == -1)
    {
        fprintf(stderr, "EVIOCGNAME failed for %s: %s\n", fname, strerror(errno));
        close(fd);
        return -1;
    } // if

    for (i = 0; !ok && (i < sizeof (known_names) / sizeof (known_names[0])); i++)
    {
        if (strncmp(buf, known_names[i], strlen(known_names[i])) == 0)
            ok = 1;
    } // for

    if (!ok)
    {
        close(fd);
        return -1;
    } // if

    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    return fd;
} // openPowermate


static void deinitPowermate(void)
{
    if (powermate_fd == -1)
    {
        setPowermateLED(0);
        close(powermate_fd);
        powermate_fd = -1;
    } // if
} // deinitPowermate


static void initPowermate(int *_argc, char **argv)
{
    const char *arg = "--powermate=";
    const size_t arglen = strlen(arg);
    int argc = *_argc;
    int i;

    for (i = 1; i < argc; i++)
    {
        const char *thisarg = argv[i];
        if (strncmp(thisarg, arg, arglen) != 0)
            continue;

        thisarg += arglen;

        if (strcmp(thisarg, "auto") == 0)
        {
            DIR *dirp = opendir("/dev/input");
            if (dirp)
            {
                struct dirent *dent;
                while ((dent = readdir(dirp)) != NULL)
                {
                    const char *name = dent->d_name;
                    char buf[PATH_MAX];
                    if (strncmp(name, "event", 5) != 0)
                        continue;
                    snprintf(buf, sizeof (buf), "/dev/input/%s", name);
                    if (powermate_fd == -1)
                    {
                        powermate_fd = openPowermate(buf);
                        if (powermate_fd != -1)
                        {
                            printf("Found Powermate at %s\n", buf);
                            break;
                        } // if
                    } // if
                } // while
                closedir(dirp);
            } // if
            thisarg = NULL;

        } // if

        // eliminate this command line.
        memmove(&argv[i], &argv[i+1], (argc-i) * sizeof (char *));
        argc--;

        if (powermate_fd == -1)
            powermate_fd = openPowermate(thisarg);
    } // for

    atexit(deinitPowermate);

    *_argc = argc;
} // initPowermate


static lua_State *luaState = NULL;
static const uint8_t zero16[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
static const char saltprefix[] = { 'S', 'a', 'l', 't', 'e', 'd', '_', '_' };

static inline int retvalStringBytes(lua_State *L, const uint8_t *str, size_t len)
{
    if (str != NULL)
        lua_pushlstring(L, (const char *) str, len);
    else
        lua_pushnil(L);
    return 1;
} // retvalStringBytes

static inline int retvalString(lua_State *L, const char *str)
{
    return retvalStringBytes(L, (const uint8_t *) str, str ? strlen(str) : 0);
} // retvalString

static inline int retvalPointer(lua_State *L, void *ptr)
{
    if (ptr != NULL)
        lua_pushlightuserdata(L, ptr);
    else
        lua_pushnil(L);
    return 1;
} // retvalPointer

static inline void xorBlock(uint8_t *dst, const uint8_t *src)
{
    int i;
    for (i = 0; i < 16; i++, dst++, src++)
        *dst ^= *src;
} // xorBlock

static int decryptUsingKeyAndIvec(uint8_t *data, size_t *datalen, const uint8_t *key, const uint8_t *iv)
{
    const size_t blocks = *datalen / 16;
    uint8_t *block = data + ((blocks-1) * 16);   // start at final block, work backwards
    const uint8_t *padding = &block[15];
    uint8_t expkey[aesExpandedKeySize];
    size_t i;

    if (blocks == 0)
        return 1;  // nothing to do.

	aesExpandKey(key, expkey);

    for (i = 0; i < blocks-1; i++)
    {
        aesDecrypt(block, expkey, block);   // decrypt in place.
        xorBlock(block, block-16);
        block -= 16;
    }
    aesDecrypt(block, expkey, block);   // decrypt in place.
    xorBlock(block, iv);   // xor against initial vector for final block.

    if (*padding > 16)
        return 0;  // bad data?

    *datalen -= *padding;

    return 1;
} // decryptBinaryUsingKeyAndIvec


static inline int isSalted(const uint8_t *data, const size_t datalen)
{
    return ( (datalen > sizeof (saltprefix)) &&
             (memcmp(data, saltprefix, sizeof (saltprefix)) == 0) );
} // isSalted


static int decryptUsingPBKDF2(lua_State *L)
{
    const char *base64 = luaL_checkstring(L, 1);
    const char *password = luaL_checkstring(L, 2);
    const int iterations = luaL_checkinteger(L, 3);
    size_t datalen = strlen(base64);
    uint8_t *dataptr = (uint8_t *) malloc(datalen);
    uint8_t *data = dataptr;
    base64_decodestate base64state;

    base64_init_decodestate(&base64state);
    datalen = base64_decode_block(base64, (int) datalen, data, &base64state);

    const uint8_t *salt = zero16;
    int saltlen = sizeof (zero16);
    if (isSalted(data, datalen))
    {
        salt = data + 8;
        saltlen = 8;
        data += 16;
        datalen -= 16;
    } // if

    uint8_t output[32];
    pkcs5_pbkdf2(password, strlen(password), salt, saltlen, output, sizeof (output), (unsigned int) iterations);

    const uint8_t *aeskey = &output[0];
    const uint8_t *aesiv = &output[16];
	if (decryptUsingKeyAndIvec(data, &datalen, aeskey, aesiv))
        retvalStringBytes(L, data, datalen);
    else
        lua_pushnil(L);

    free(dataptr);
    return 1;
} // decryptUsingPBKDF2


static int decryptBase64UsingKey(lua_State *L)
{
    size_t keylen = 0;
    const char *base64 = luaL_checkstring(L, 1);
    const uint8_t *key = (const uint8_t *) luaL_checklstring(L, 2, &keylen);
    size_t datalen = strlen(base64);
    uint8_t *dataptr = (uint8_t *) malloc(datalen);
    uint8_t *data = dataptr;
    base64_decodestate base64state;

    base64_init_decodestate(&base64state);
    datalen = base64_decode_block(base64, (int) datalen, data, &base64state);

    uint8_t aeskey[16];
    uint8_t aesiv[16];
    MD5_CTX md5;

    if (isSalted(data, datalen))
    {
        const uint8_t *salt = data + 8;
        const size_t saltlen = 8;
        data += 16;
        datalen -= 16;

        assert(aesNr == 10);  // AES-256 needs more rounds.
        assert(aesNk == 4);   // hashing size is hardcoded later.
        uint8_t hashing[32];

        MD5_init(&md5);
        MD5_append(&md5, key, keylen);
        MD5_append(&md5, salt, saltlen);
        MD5_finish(&md5, hashing);

        MD5_init(&md5);
        MD5_append(&md5, hashing, 16);
        MD5_append(&md5, key, keylen);
        MD5_append(&md5, salt, saltlen);
        MD5_finish(&md5, &hashing[16]);

        memcpy(aeskey, hashing, 4 * aesNk);
        memcpy(aesiv, &hashing[4 * aesNk], 16);
    } // if
    else
    {
        MD5_init(&md5);
        MD5_append(&md5, key, keylen);
        MD5_finish(&md5, aeskey);
        memset(aesiv, '\0', sizeof (aesiv));
    } // else

	if (decryptUsingKeyAndIvec(data, &datalen, aeskey, aesiv))
        retvalStringBytes(L, data, datalen);
    else
        lua_pushnil(L);

    free(dataptr);
    return 1;
} // decryptBase64UsingKey


static int runGuiPasswordPrompt(lua_State *L)
{
    const char *hintstr = lua_tostring(L, 1);
    GtkWidget *dialog = gtk_dialog_new_with_buttons(
                            "Master Password", NULL, GTK_DIALOG_MODAL,
                            GTK_STOCK_CANCEL, GTK_RESPONSE_REJECT,
                            GTK_STOCK_OK, GTK_RESPONSE_ACCEPT,
                            NULL);

    GtkWidget *content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));

    if (hintstr != NULL)
    {
        GtkWidget *label = gtk_label_new(hintstr);
        gtk_label_set_justify(GTK_LABEL(label), GTK_JUSTIFY_CENTER);
        gtk_container_add(GTK_CONTAINER(content_area), label);
    } // if

    GtkWidget *entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
    gtk_entry_set_activates_default(GTK_ENTRY(entry), TRUE);
    gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_ACCEPT);
    gtk_container_add(GTK_CONTAINER(content_area), entry);

    gtk_window_set_position(GTK_WINDOW(dialog), GTK_WIN_POS_MOUSE);
    gtk_widget_show_all(dialog);
    gtk_window_set_keep_above(GTK_WINDOW(dialog), TRUE);
    const int ok = (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT);
    retvalString(L, ok ? (const char *) gtk_entry_get_text(GTK_ENTRY(entry)) : NULL);
    gtk_widget_destroy(dialog);

    return 1;
} // runGuiPasswordPrompt


static int copyToClipboard(lua_State *L)
{
    const char *str = luaL_checkstring(L, 1);
    gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_PRIMARY), str, -1);
    gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_CLIPBOARD), str, -1);
} // copyToClipboard


static int makeGuiMenu(lua_State *L)
{
    return retvalPointer(L, gtk_menu_new());
} // makeGuiMenu


static void clickedMenuItem(void *arg)
{
    // This is the callback from GTK+; now call into our actual Lua callback!
    const int callback = (int) ((size_t)arg);
    lua_rawgeti(luaState, LUA_REGISTRYINDEX, callback);
    lua_call(luaState, 0, 0);
} // clickedMenuItem

#if 0  // !!! FIXME: figure out how to fire this.
static void deletedMenuItem(void *arg)
{
    // Clean up the Lua function we referenced in the Registry.
    const int callback = (int) ((size_t)arg);
printf("unref callback %d\n", callback);
    luaL_unref(luaState, LUA_REGISTRYINDEX, callback);
} // deletedMenuItem
#endif

static int appendGuiMenuItem(lua_State *L)
{
    const int argc = lua_gettop(L);
    GtkWidget *menu = (GtkWidget *) lua_touserdata(L, 1);
    const char *label = luaL_checkstring(L, 2);
    GtkWidget *item = gtk_menu_item_new_with_label(label);

    if ((argc >= 3) && (!lua_isnil(L, 3)))
    {
        assert(lua_isfunction(L, 3));
        lua_pushvalue(L, 3);  // copy the Lua callback (luaL_ref() pops it).
        const int callback = luaL_ref(L, LUA_REGISTRYINDEX);
        gtk_signal_connect_object(GTK_OBJECT(item), "activate", GTK_SIGNAL_FUNC(clickedMenuItem), (gpointer) ((size_t)callback));
    } // if

    gtk_widget_show(item);
    gtk_menu_append(menu, item);
    return retvalPointer(L, item);
} // appendGuiMenuItem


static int setGuiMenuItemSubmenu(lua_State *L)
{
    GtkMenuItem *item = (GtkMenuItem *) lua_touserdata(L, 1);
    GtkWidget *submenu = (GtkWidget *) lua_touserdata(L, 2);
    gtk_menu_item_set_submenu(item, submenu);
    return 0;
} // setGuiMenuItemSubmenu


static int popupGuiMenu(lua_State *L)
{
    GtkMenu *menu = (GtkMenu *) lua_touserdata(L, 1);
    gtk_menu_popup(menu, NULL, NULL, NULL, NULL, 0, gtk_get_current_event_time());
    return 0;
} // popupGuiMenu


static int setPowermateLED_Lua(lua_State *L)
{
    const int enable = lua_toboolean(L, 1);
    setPowermateLED(enable);
    return 0;
} // setPowermateLED_Lua


static void keyhookPressed(void)
{
    lua_getglobal(luaState, "keyhookPressed");
    lua_call(luaState, 0, 0);
} // keyhookPressed


static int pumpLua(void)
{
    lua_getglobal(luaState, "pumpLua");
    lua_call(luaState, 0, 0);
} // pumpLua


static gboolean keyhookPumper(void *arg)
{
    pumpLua();
    if (pumpKeyHook())
        keyhookPressed();
    else if (pumpPowermate())
        keyhookPressed();

    return TRUE;  // keep firing timer
} // keyhookPumper


static int giveControlToGui(lua_State *L)
{
    if (initKeyHook())
    {
        atexit(deinitKeyHook);
        g_timeout_add(200, (GSourceFunc) keyhookPumper, (gpointer) NULL);
    } // if

    gtk_main();
    return 0;
} // giveControlToGui


static void *luaAlloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
    if (nsize == 0)
    {
        free(ptr);
        return NULL;
    } // if
    return realloc(ptr, nsize);
} // luaAlloc


static inline void luaSetCFunc(lua_State *L, lua_CFunction f, const char *sym)
{
    lua_pushcfunction(L, f);
    lua_setglobal(luaState, sym);
} // luaSetCFunc


static int luaFatal(lua_State *L)
{
    const char *errstr = lua_tostring(L, -1);
    fprintf(stderr, "Lua panic: %s\n", errstr ? errstr : "(?)");
    fflush(stderr);
    exit(1);
} // luaFatal


static void deinitLua(void)
{
    if (luaState != NULL)
    {
        lua_close(luaState);
        luaState = NULL;
    } // if
} // deinitLua


static int initLua(const int argc, char **argv)
{
    atexit(deinitLua);

    assert(luaState == NULL);
    luaState = lua_newstate(luaAlloc, NULL);

    lua_atpanic(luaState, luaFatal);
    assert(lua_checkstack(luaState, 20));  // Just in case.
    luaL_openlibs(luaState);

    // Set up initial C functions, etc we want to expose to Lua code...
    luaSetCFunc(luaState, decryptUsingPBKDF2, "decryptUsingPBKDF2");
    luaSetCFunc(luaState, decryptBase64UsingKey, "decryptBase64UsingKey");
    luaSetCFunc(luaState, makeGuiMenu, "makeGuiMenu");
    luaSetCFunc(luaState, appendGuiMenuItem, "appendGuiMenuItem");
    luaSetCFunc(luaState, setGuiMenuItemSubmenu, "setGuiMenuItemSubmenu");
    luaSetCFunc(luaState, popupGuiMenu, "popupGuiMenu");
    luaSetCFunc(luaState, giveControlToGui, "giveControlToGui");
    luaSetCFunc(luaState, runGuiPasswordPrompt, "runGuiPasswordPrompt");
    luaSetCFunc(luaState, copyToClipboard, "copyToClipboard");
    luaSetCFunc(luaState, setPowermateLED_Lua, "setPowermateLED");

    // Set up argv table...
    lua_newtable(luaState);
    int i;
    int luai = 1;
    for (i = 0; i < argc; i++)
    {
        if (argv[i])
        {
            lua_pushinteger(luaState, luai);
            lua_pushstring(luaState, argv[i]);
            lua_settable(luaState, -3);
            luai++;
        } // if
    } // for
    lua_setglobal(luaState, "argv");

    // Transfer control to Lua...
    if (luaL_dofile(luaState, "1pass.lua") != 0)
        luaFatal(luaState);

    return 1;
} // initLua


static void deinitAll()
{
    deinitPowermate();
    deinitKeyHook();
    deinitLua();
} // deinitAll


static void killerSignalCatcher(int sig)
{
    static int been_run = 0;
    if (been_run)
    {
        fprintf(stderr, "Caught signal %d, terminating HARD.\n", sig);
        _exit(0);
    } // if

    been_run = 1;
    fprintf(stderr, "Caught signal %d, terminating.\n", sig);
    exit(0);  // trigger atexit handlers.
} // killerSignalCatcher


static void initSignals(void)
{
    signal(SIGINT, killerSignalCatcher);
    signal(SIGQUIT, killerSignalCatcher);
    signal(SIGILL, killerSignalCatcher);
    signal(SIGFPE, killerSignalCatcher);
    signal(SIGTERM, killerSignalCatcher);
    signal(SIGPIPE, killerSignalCatcher);
    signal(SIGSEGV, killerSignalCatcher);
    signal(SIGABRT, killerSignalCatcher);
    signal(SIGHUP, killerSignalCatcher);
} // initSignals


int main(int argc, char **argv)
{
    initSignals();
    initPowermate(&argc, argv);
    gtk_init(&argc, &argv);

    if (!initLua(argc, argv))  // this will move control to 1pass.lua
        return 1;

    return 0;
} // main

// end of 1pass.c ...

