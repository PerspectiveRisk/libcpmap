// Copyright (c) 2019-2020 Calum Ewart Hutton
// Distributed under the GNU General Public License v3.0+, see the accompanying
// file LICENSE or https://opensource.org/licenses/GPL-3.0.

package lib.chutchut.cpmap.payload.adapter;

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;

import java.lang.reflect.Type;

import lib.chutchut.cpmap.payload.HeuristicPayload;
import lib.chutchut.cpmap.payload.base.Payload;


public class PayloadAdapter implements JsonSerializer<Payload>, JsonDeserializer<Payload> {

    @Override
    public Payload deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
        JsonObject jsonObject = json.getAsJsonObject();
        String type = jsonObject.get("type").getAsString();
        JsonElement element = jsonObject.get("properties");

        // Use the heuristic payload class to get the right package name
        // (its in the same package as classes to be serialised/de-serialised)
        String payloadClass = HeuristicPayload.class.getPackage().getName() + "." + type;

        try {
            return context.deserialize(element, Class.forName(payloadClass));
        } catch (ClassNotFoundException cnfe) {
            throw new JsonParseException("Unknown element type: " + payloadClass, cnfe);
        }
    }

    @Override
    public JsonElement serialize(Payload src, Type typeOfSrc, JsonSerializationContext context) {
        JsonObject result = new JsonObject();
        result.add("type", new JsonPrimitive(src.getClass().getSimpleName()));
        result.add("properties", context.serialize(src, src.getClass()));
        return result;
    }
}
