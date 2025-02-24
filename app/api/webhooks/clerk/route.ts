/* eslint-disable camelcase */
import { clerkClient } from '@clerk/express'
import { WebhookEvent } from "@clerk/nextjs/server";
import { headers } from "next/headers";
import { NextResponse } from "next/server";
import { Webhook } from "svix";

import { createUser, deleteUser, updateUser } from "@/lib/actions/user.actions";

export async function POST(req: Request) {
  
  try {
    const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;
    if (!WEBHOOK_SECRET) {
      throw new Error("WEBHOOK_SECRET is missing in environment variables.");
    }

    const headerPayload = headers();
    const svix_id = headerPayload.get("svix-id");
    const svix_timestamp = headerPayload.get("svix-timestamp");
    const svix_signature = headerPayload.get("svix-signature");

    if (!svix_id || !svix_timestamp || !svix_signature) {
      return NextResponse.json(
        { error: "Missing required Svix headers." },
        { status: 400 }
      );
    }

    const payload = await req.json();
    const body = JSON.stringify(payload);

    const wh = new Webhook(WEBHOOK_SECRET);
    let evt: WebhookEvent;

    try {
      evt = wh.verify(body, {
        "svix-id": svix_id,
        "svix-timestamp": svix_timestamp,
        "svix-signature": svix_signature,
      }) as WebhookEvent;
    } catch (err) {
      console.error("Error verifying webhook:", err);
      return NextResponse.json(
        { error: "Webhook verification failed." },
        { status: 400 }
      );
    }

    const { id } = evt.data;
    const eventType = evt.type;

    switch (eventType) {
      case "user.created": {
        const { email_addresses, image_url, first_name, last_name, username } = evt.data;
        const user = {
          clerkId: id ?? "", // Ensure it's always a string
          email: email_addresses?.[0]?.email_address || "",
          username: username || "",
          firstName: first_name || "",
          lastName: last_name || "",
          photo: image_url || "",
        };

        const newUser = await createUser(user);

        if (newUser) {
          await clerkClient.users.updateUserMetadata(id ?? "", {
            publicMetadata: { userId: newUser._id },
          });
          
        }

        return NextResponse.json({ message: "User created successfully.", user: newUser });
      }

      case "user.updated": {
        const { image_url, first_name, last_name, username } = evt.data;
        const user = {
          firstName: first_name || "",
          lastName: last_name || "",
          username: username || "",
          photo: image_url || "",
        };

        const updatedUser = await updateUser(id ?? "", user);
        return NextResponse.json({ message: "User updated successfully.", user: updatedUser });
      }

      case "user.deleted": {
        const deletedUser = await deleteUser(id ?? "");
        return NextResponse.json({ message: "User deleted successfully.", user: deletedUser });
      }

      default:
        console.warn(`Unhandled event type: ${eventType}`);
        return NextResponse.json({ message: "Unhandled event type." }, { status: 400 });
    }
  } catch (error) {
    console.error("Unexpected error:", error);
    return NextResponse.json({ error: "Internal server error." }, { status: 500 });
  }
}
